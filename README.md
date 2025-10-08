# Minimal OAuth2 Authorization Server (Flask + Authlib + SQLAlchemy)

This repository contains a minimal OAuth 2.0 Authorization Server built with Flask and Authlib, using SQLAlchemy with SQLite for storage. It demonstrates the Authorization Code grant (with optional PKCE), consent screen, refresh tokens (rotation), scopes, and a simple username/password login.

## Features

- **OIDC-ready**: Discovery (`/.well-known/openid-configuration`), JWKS (`/.well-known/jwks.json`), `userinfo`
- **ID tokens (RS256)** when `openid` scope is requested (opaque access tokens by default; JWT optional per policy)
- **Authorization Code grant** with **PKCE (S256)**
- **Consent screen** with per-client consent policy (`always` | `once` | `skip`)
- **Refresh tokens** (rotation)
- **Scopes** stored in DB with descriptions and claims (no hardcoding)
- **Admin Web UI** to manage Scopes, Clients, Policies, and Signing Keys
- **First-time setup wizard** to generate and store a hashed Admin Token
- **Admin APIs** (secured by `X-Admin-Token`) to automate configuration
- **Dev helpers gated** by `ENABLE_DEV_ENDPOINTS=true` (seed, PKCE, quick client creation)

Stack:
- **Flask** (web framework)
- **Authlib** (OAuth 2.0 / OIDC)
- **SQLAlchemy** (ORM; SQLite for demo)

> Note: The server issues OIDC `id_token` (RS256) when `openid` is requested. Access tokens are opaque by default and can be switched to JWT per client policy.

---

## Requirements

- Python 3.10+
- pip (or use [uv](https://docs.astral.sh/uv/))

## Installation

Using uv (recommended):

```bash
uv run server.py
```

Using pip:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install flask authlib sqlalchemy
python server.py
```

## Configuration

Environment variables:

- `APP_SECRET`: Flask session secret. If unset, a random value is used for dev.
- `DATABASE_URL`: SQLAlchemy URL. Default: `sqlite:///oauth.db`
  - For SQLite, the file is created at the project root as `oauth.db`.
- `ENABLE_DEV_ENDPOINTS`: If `true|1|yes|on`, enables dev routes (`/dev/*`). These still require `X-Admin-Token`.
- `ADMIN_TOKEN`: Optional bootstrap token accepted only if setup has not been completed. After setup, the hashed token stored in DB is required instead.

## Run the Server

```bash
uv run server.py
# App starts at http://127.0.0.1:5000
```

On first run, you will be redirected to `GET /setup` to initialize the server and set an Admin Token (shown once, then hashed in DB). Use this token to access the Admin UI and Admin APIs.

## Seed Demo Data (dev only)

Dev routes are disabled by default. To enable:

```bash
export ENABLE_DEV_ENDPOINTS=true
uv run server.py
```

Then, with your Admin Token from setup:

```bash
curl http://127.0.0.1:5000/dev/seed \
  -H "X-Admin-Token: <YOUR_SETUP_TOKEN>"
```

Seeds demo users (`alice/alice`, `bob/bob`) and a public client `demo-web` suitable for local demos.

## PKCE Helper (dev only)

When `ENABLE_DEV_ENDPOINTS=true`:

```bash
curl http://127.0.0.1:5000/dev/pkce \
  -H "X-Admin-Token: <YOUR_SETUP_TOKEN>"
```

Returns JSON with `code_verifier` and `code_challenge` for S256 usage:

```json
{
  "code_verifier": "...",
  "code_challenge": "...",
  "method": "S256"
}
```

> If you include `code_challenge_method=S256` in your `/authorize` request, you must also include a non-empty `code_challenge`. Otherwise you will receive HTTP 400.

## OAuth 2.0/OIDC Authorization Code Flow (Step-by-Step)

1. **Create a client**
   - Open Admin UI: `http://127.0.0.1:5000/admin/login` (use Admin Token).
   - Create a client with:
     - Redirect URI: your app’s callback (e.g., `http://localhost:3000/callback`)
     - Grant types: `authorization_code refresh_token`
     - Response types: `code`
     - Scope: `openid profile email offline_access`
     - Public client: checked (if SPA/native) → PKCE required by policy.

2. **Generate PKCE (public clients)**
   - If dev helper is enabled: `GET /dev/pkce` or generate in your app.

3. **Authorize request**
   - Open in the browser (replace `<CHALLENGE>` if using PKCE):
     ```
     http://127.0.0.1:5000/authorize?
       client_id=demo-web&
       response_type=code&
       scope=openid%20profile%20email%20offline_access&
       redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&
       code_challenge_method=S256&
       code_challenge=<CHALLENGE>
     ```
   - Log in as `alice/alice` when prompted.
   - Review the consent screen and click Allow.
   - You will be redirected to `redirect_uri` with `?code=...`.

4. **Exchange code for tokens**
   - Example with curl (replace placeholders):
     ```bash
     curl -X POST http://127.0.0.1:5000/token \
          -H 'Content-Type: application/x-www-form-urlencoded' \
          -d 'grant_type=authorization_code' \
          -d 'client_id=demo-web' \
          -d 'code_verifier=<VERIFIER>' \
          -d 'code=<CODE_FROM_CALLBACK>' \
          -d 'redirect_uri=http://localhost:3000/callback'
     ```
   - Response includes `access_token`, `refresh_token`, `token_type`, `expires_in`, and `scope`.

5. **Call a protected API**
   - Requires `Authorization: Bearer <access_token>` and appropriate scope.
   - Example:
     ```bash
     curl http://127.0.0.1:5000/userinfo \
          -H 'Authorization: Bearer <access_token>'
     ```

6. **Refresh the access token**
   - Example with curl:
     ```bash
     curl -X POST http://127.0.0.1:5000/token \
          -H 'Content-Type: application/x-www-form-urlencoded' \
          -d 'grant_type=refresh_token' \
          -d 'client_id=demo-web' \
          -d 'refresh_token=<REFRESH_TOKEN>'
     ```
   - Refresh tokens are rotated. Old refresh tokens are revoked.

## API Endpoints

- **OIDC Discovery**: `GET /.well-known/openid-configuration`
- **JWKS**: `GET /.well-known/jwks.json`
- **Authorize**: `GET/POST /authorize`
- **Token**: `POST /token`
- **UserInfo**: `GET /userinfo`
- **End Session (logout)**: `GET /end_session` and app-level `GET /logout`
- **Revoke**: `POST /revoke` (client auth required)
- **Introspect**: `POST /introspect` (client auth required)
- **Admin UI**: `GET /admin/login`, `GET /admin/ui`, `GET/POST /admin/ui/scopes`, `GET/POST /admin/ui/clients`, `GET/POST /admin/ui/clients/<client_id>`, `GET/POST /admin/ui/keys`
- **Admin APIs**: `GET/POST /admin/scopes`, `DELETE /admin/scopes/<name>`, `GET/POST /admin/clients/<client_id>/policy`, `POST /admin/rotate_jwk` (all require `X-Admin-Token`)
- **Dev (gated)**: `GET /dev/seed`, `POST /dev/create_client`, `GET /dev/pkce` (require `ENABLE_DEV_ENDPOINTS=true` and `X-Admin-Token`)

## Data Model (brief)

- `user`: id, username, password_hash, email
- `oauth2_client`: client_id, client_secret, grant_types, redirect_uris, response_types, scope, token_endpoint_auth_method, require_consent, etc.
- `oauth2_code`: authorization code storage with PKCE fields
- `oauth2_token`: access/refresh tokens, expiry, scope, revoked flag

## Customization

- Define scopes and descriptions via Admin UI (`/admin/ui/scopes`) or Admin API.
- Strict redirect URI matching is enforced by `OAuth2Client.check_redirect_uri()`.
- Configure per-client policy (allowed/default scopes, PKCE, consent policy, token lifetimes, token format) via Admin UI or API.

## Troubleshooting

- **[Admin login fails]** Ensure you use the token shown on the setup success screen. Whitespace matters (we trim both sides, but double-check copy/paste). If you lost it, reset by updating the `server_settings.admin_token_hash` in DB or reinitializing the database.
- **[401 Admin API]** Send `X-Admin-Token: <token>` header. After setup, env `ADMIN_TOKEN` is ignored.
- **[Dev endpoints 404]** Set `ENABLE_DEV_ENDPOINTS=true` and include `X-Admin-Token`.
- **[400 invalid redirect_uri]** The `redirect_uri` must exactly match one of the client’s registered URIs.
- **[400 PKCE required]** Client policy may require PKCE (S256). Include `code_challenge_method=S256` and `code_challenge` on `/authorize`, and `code_verifier` on `/token`.
- **[No id_token]** Include the `openid` scope.
- **[Logout doesn’t return]** Add your app URL to client policy `post_logout_redirect_uris`.
- **[Consent remembered]** With policy `once`, consent is remembered per user+client+scope. Use `always` to force consent each time.
- **[SQLite locking]** SQLite is fine for dev. Use Postgres/MySQL and a production WSGI server for prod.
- **[Token validation]** If you switch to JWT access tokens, verify `iss`/`aud` via JWKS and configured issuer.

## Production Notes

- **HTTPS + reverse proxy**: Terminate TLS at a proxy (nginx, ALB) and forward to a WSGI app server (gunicorn/uWSGI).
- **Real DB**: Use Postgres/MySQL. Configure `DATABASE_URL` and run with proper connection pooling.
- **Secrets**: Set strong `APP_SECRET`. Store secrets in a secret manager.
- **Issuer**: Ensure consistent public base URL (e.g., behind a proxy) so discovery `issuer` is stable.
- **Clients and scopes**: Manage via Admin UI/API; avoid wildcards in `redirect_uris`.
- **Security**: Replace demo login, add CSRF protection for admin forms, enable rate limiting.
- **Key management**: Rotate signing keys periodically via Admin UI; back up the database (contains keys and settings).

---

## Admin UI Reference

Use this section as an in-app guide from the Admin UI. The info icons on forms link to each subsection below.

### Overview

- **Dashboard**: `/admin/ui` shows quick links to Scopes, Clients, and Signing Keys.
- **Docs**: `/admin/ui/docs` renders this README for inline help.

### Clients

Create and manage OAuth2/OIDC clients that integrate with this Authorization Server.

#### Client Fields

### Client ID
- Unique identifier for the client. Use a simple, stable, URL-safe value.
- Examples: `my-app`, `camera-web`, `todo-spa`.

### Client Name
- Human-readable name shown on consent screens.
- Example: `My Camera App`.

### Redirect URIs
- Space- or newline-separated list of exact callback URLs.
- Must match the `redirect_uri` in authorize/token requests exactly.
- Examples:
  - `http://localhost:3000/callback`
  - `https://myapp.example.com/auth/callback`

### Client Scope
- Space-separated scopes the client will request.
- Common: `openid profile email offline_access`.
- Must also be allowed by the client policy (see Allowed Scopes below).

### Grant Types
- OAuth2 flows permitted for this client.
- Common: `authorization_code refresh_token`.
- Public clients (SPAs/native) should use Authorization Code with PKCE.

### Response Types
- Authorization response modes. Commonly `code`.

### Client Type
- Public clients: No client secret; must use PKCE (recommended for SPAs/native).
- Confidential clients: Server-side apps that keep a client secret; choose an auth method.

### Token Endpoint Auth Method
- How confidential clients authenticate at `/token`.
- Options: `none` (public), `client_secret_post`, `client_secret_basic`.

### Require Consent
- If enabled, the user must approve on the consent screen before tokens are issued.
- Use together with the Client Policy's Consent Policy (below) to control how often consent is shown.

#### Client Policy

### Allowed Scopes
- Space-separated list of scopes this client is permitted to request.
- Requests outside this set will be rejected.

### Default Scopes
- Scopes automatically applied when an authorize request does not specify `scope`.

### Post-Logout Redirect URIs
- Space-separated list of URLs users may be redirected to after logout.
- Used by `GET /end_session`.

### Require PKCE
- Enforces PKCE S256 for Authorization Code flow.
- Strongly recommended for public clients.

### Consent Policy
- Controls consent prompting.
- `always`: ask every time.
- `once`: remember consent per user+client+scope.
- `skip`: never show consent screen.

### Access Token Lifetime (seconds)
- How long access tokens remain valid. Typical prod default: `3600` (1 hour).

### Refresh Token TTL (days)
- How long refresh tokens remain valid. Tokens are rotated on use.

### Token Format
- `opaque` (default): access token is a reference stored server-side.
- `jwt` (optional): self-contained access token signed by the server (verify via JWKS).

### Scopes

- Define scopes (name, description, claims) in `/admin/ui/scopes`.
- Scopes appear on consent screens with their descriptions.
- Claims listed on a scope can be used to derive ID token or UserInfo content per your implementation.

### Signing Keys

- Manage and rotate RS256 signing keys in `/admin/ui/keys`.
- JWKS is published at `/.well-known/jwks.json`.
- Rotating keys preserves old keys to validate historical tokens.

### First-time Setup

- On first run, visit `/setup` to initialize the server and create the Admin Token.
- The token is shown once and then stored hashed in the DB. Keep it secure.
- Use the token for Admin UI login and as `X-Admin-Token` for Admin APIs.

### Dev Endpoints (optional)

- Disabled by default; set `ENABLE_DEV_ENDPOINTS=true` to enable `GET /dev/seed`, `GET /dev/pkce`, `POST /dev/create_client`.
- Still require `X-Admin-Token` when enabled.

---

## License

MIT

