import crypto from "crypto"
import type { Context, Hono } from "hono"

// ---------------------------------------------------------------------------
// OAuth 2.1 endpoints for Claude Desktop "Custom Connector" support.
//
// Claude Desktop's Custom Connector UI only accepts a Client ID / Client
// Secret (no bearer header field), so this module implements the minimal
// OAuth 2.1 discovery + authorization_code + refresh_token flow that
// Claude.ai / Claude Desktop / Claude Code speak:
//
//   GET  /.well-known/oauth-protected-resource   (RFC 9728)
//   GET  /.well-known/oauth-authorization-server (RFC 8414)
//   GET  /authorize      → redirects to redirect_uri with ?code=…&state=…
//   POST /token          → exchanges code for JWT access_token (+refresh)
//   POST /register       → Dynamic Client Registration (RFC 7591, minimal)
//
// The server is a single-tenant "personal" OAuth server: there is exactly
// one pre-configured client (OAUTH_CLIENT_ID/SECRET) and the /authorize
// endpoint auto-approves without an interactive login, because proving
// possession of OAUTH_CLIENT_SECRET at /token is the authentication step.
// ---------------------------------------------------------------------------

export interface OAuthConfig {
  publicUrl: string // canonical issuer URL, no trailing slash
  clientId: string
  clientSecret: string
  jwtSecret: string // HS256 signing secret for issued access/refresh tokens
  accessTokenTtlSeconds?: number
  refreshTokenTtlSeconds?: number
}

interface CodeEntry {
  clientId: string
  codeChallenge: string
  redirectUri: string
  scope: string | null
  expiresAt: number
}

// In-memory code store. Codes are one-shot and short-lived (5 min), so
// losing them on restart is acceptable.
const codeStore = new Map<string, CodeEntry>()

function b64url(buf: Buffer | string): string {
  const b = typeof buf === "string" ? Buffer.from(buf) : buf
  return b.toString("base64url")
}

function signJwt(payload: Record<string, unknown>, secret: string): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))
  const body = b64url(JSON.stringify(payload))
  const signingInput = `${header}.${body}`
  const signature = b64url(crypto.createHmac("sha256", secret).update(signingInput).digest())
  return `${signingInput}.${signature}`
}

export function verifyJwt(token: string, secret: string): Record<string, unknown> | null {
  const parts = token.split(".")
  if (parts.length !== 3) return null
  const [header, body, signature] = parts
  const expected = b64url(crypto.createHmac("sha256", secret).update(`${header}.${body}`).digest())
  const a = Buffer.from(signature)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString()) as Record<string, unknown>
    const { exp } = payload
    if (typeof exp === "number" && exp < Math.floor(Date.now() / 1000)) return null
    return payload
  } catch {
    return null
  }
}

function getBasicAuthSecret(c: Context): string | null {
  const auth = c.req.header("authorization")
  if (!auth?.startsWith("Basic ")) return null
  try {
    const decoded = Buffer.from(auth.slice(6), "base64").toString()
    const idx = decoded.indexOf(":")
    return idx === -1 ? null : decoded.slice(idx + 1)
  } catch {
    return null
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) return false
  return crypto.timingSafeEqual(ab, bb)
}

function pruneExpiredCodes(): void {
  const now = Date.now()
  for (const [code, entry] of codeStore) {
    if (entry.expiresAt < now) codeStore.delete(code)
  }
}

export function registerOAuthRoutes(app: Hono, config: OAuthConfig): void {
  const { publicUrl, clientId, clientSecret, jwtSecret } = config
  const accessTtl = config.accessTokenTtlSeconds ?? 3600
  const refreshTtl = config.refreshTokenTtlSeconds ?? 30 * 24 * 3600

  // RFC 9728 - Protected Resource Metadata
  // Both root and /mcp-scoped versions because different MCP clients probe
  // different paths.
  const protectedResource = {
    resource: publicUrl,
    authorization_servers: [publicUrl],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  }
  app.get("/.well-known/oauth-protected-resource", (c) => c.json(protectedResource))
  app.get("/.well-known/oauth-protected-resource/mcp", (c) => c.json(protectedResource))

  // RFC 8414 - Authorization Server Metadata
  app.get("/.well-known/oauth-authorization-server", (c) =>
    c.json({
      issuer: publicUrl,
      authorization_endpoint: `${publicUrl}/authorize`,
      token_endpoint: `${publicUrl}/token`,
      registration_endpoint: `${publicUrl}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
      scopes_supported: ["mcp"],
    }),
  )

  // Dynamic Client Registration (RFC 7591) - minimal implementation that
  // always returns the pre-configured client. Claude Desktop falls back to
  // DCR when Advanced Settings are empty; when they're filled in it uses
  // those creds directly and never hits /register.
  app.post("/register", async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      client_name?: string
      redirect_uris?: string[]
      grant_types?: string[]
      response_types?: string[]
      token_endpoint_auth_method?: string
    }
    return c.json(
      {
        client_id: clientId,
        client_name: body.client_name ?? "reddit-mcp-server-client",
        redirect_uris: body.redirect_uris ?? [],
        grant_types: body.grant_types ?? ["authorization_code", "refresh_token"],
        response_types: body.response_types ?? ["code"],
        token_endpoint_auth_method: body.token_endpoint_auth_method ?? "client_secret_post",
        client_id_issued_at: Math.floor(Date.now() / 1000),
      },
      201,
    )
  })

  // Authorization endpoint - auto-approves (no consent UI) because the
  // only legitimate caller is someone who already knows client_secret.
  app.get("/authorize", (c) => {
    const url = new URL(c.req.url)
    const p = url.searchParams
    const responseType = p.get("response_type")
    const reqClientId = p.get("client_id")
    const redirectUri = p.get("redirect_uri")
    const codeChallenge = p.get("code_challenge")
    const codeChallengeMethod = p.get("code_challenge_method")
    const scope = p.get("scope")
    const state = p.get("state")

    if (responseType !== "code") return c.text("invalid_request: response_type must be 'code'", 400)
    if (reqClientId !== clientId) return c.text("invalid_client", 400)
    if (redirectUri === null || redirectUri === "") return c.text("invalid_request: redirect_uri required", 400)
    if (codeChallenge === null || codeChallenge === "") return c.text("invalid_request: code_challenge required", 400)
    if (codeChallengeMethod !== "S256") return c.text("invalid_request: code_challenge_method must be S256", 400)

    pruneExpiredCodes()
    const code = crypto.randomBytes(32).toString("hex")
    codeStore.set(code, {
      clientId,
      codeChallenge,
      redirectUri,
      scope,
      expiresAt: Date.now() + 5 * 60 * 1000,
    })

    const location = new URL(redirectUri)
    location.searchParams.set("code", code)
    if (state !== null && state !== "") location.searchParams.set("state", state)
    return c.redirect(location.toString(), 302)
  })

  // Token endpoint
  app.post("/token", async (c) => {
    const body = (await c.req.parseBody()) as Record<string, string | undefined>
    const grantType = body.grant_type ?? ""

    if (grantType === "authorization_code") {
      const code = body.code ?? ""
      const codeVerifier = body.code_verifier ?? ""
      const redirectUri = body.redirect_uri ?? ""
      const reqClientId = body.client_id ?? ""
      const reqClientSecret = body.client_secret ?? getBasicAuthSecret(c) ?? ""

      const entry = codeStore.get(code)
      if (entry === undefined) return c.json({ error: "invalid_grant" }, 400)
      codeStore.delete(code)
      if (entry.expiresAt < Date.now())
        return c.json({ error: "invalid_grant", error_description: "code expired" }, 400)
      if (entry.redirectUri !== redirectUri)
        return c.json({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, 400)
      if (entry.clientId !== reqClientId) return c.json({ error: "invalid_client" }, 400)

      // Verify PKCE
      const computedChallenge = b64url(crypto.createHash("sha256").update(codeVerifier).digest())
      if (!constantTimeEqual(computedChallenge, entry.codeChallenge))
        return c.json({ error: "invalid_grant", error_description: "code_verifier mismatch" }, 400)

      // Verify client secret (required when configured)
      if (clientSecret !== "" && !constantTimeEqual(reqClientSecret, clientSecret))
        return c.json({ error: "invalid_client" }, 401)

      const now = Math.floor(Date.now() / 1000)
      const accessToken = signJwt(
        {
          iss: publicUrl,
          aud: publicUrl,
          sub: "mcp-user",
          scope: entry.scope ?? "mcp",
          iat: now,
          exp: now + accessTtl,
        },
        jwtSecret,
      )
      const refreshToken = signJwt(
        { iss: publicUrl, sub: "mcp-user", typ: "refresh", iat: now, exp: now + refreshTtl },
        jwtSecret,
      )

      return c.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: accessTtl,
        refresh_token: refreshToken,
        scope: entry.scope ?? "mcp",
      })
    }

    if (grantType === "refresh_token") {
      const refreshToken = body.refresh_token ?? ""
      const reqClientId = body.client_id ?? ""
      const reqClientSecret = body.client_secret ?? getBasicAuthSecret(c) ?? ""

      if (reqClientId !== "" && reqClientId !== clientId) return c.json({ error: "invalid_client" }, 401)
      if (clientSecret !== "" && reqClientSecret !== "" && !constantTimeEqual(reqClientSecret, clientSecret))
        return c.json({ error: "invalid_client" }, 401)

      const payload = verifyJwt(refreshToken, jwtSecret)
      if (payload?.typ !== "refresh") return c.json({ error: "invalid_grant" }, 400)

      const now = Math.floor(Date.now() / 1000)
      const accessToken = signJwt(
        { iss: publicUrl, aud: publicUrl, sub: "mcp-user", scope: "mcp", iat: now, exp: now + accessTtl },
        jwtSecret,
      )
      return c.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: accessTtl,
        scope: "mcp",
      })
    }

    return c.json({ error: "unsupported_grant_type" }, 400)
  })
}

export function buildWwwAuthenticateHeader(publicUrl: string): string {
  return `Bearer realm="mcp", resource_metadata="${publicUrl}/.well-known/oauth-protected-resource"`
}
