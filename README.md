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
# App starts at http://127.0.0.1:8000 (fixed)
```

On first run, you will be redirected to `GET /setup` to initialize the server and set an Admin Token (shown once, then hashed in DB). Use this token to access the Admin UI and Admin APIs.

### Ports

- **Authorization Server (AS)**: `127.0.0.1:8000` (fixed in `server.py`).
- **Demo apps**: `localhost:3000` (todo demo) and `localhost:3001` (camera demo) by default.

### Quickstart (60 seconds)

1. Set dev env and start (enables helpers):
   ```bash
   export ENABLE_DEV_ENDPOINTS=true
   uv run server.py
   export BASE=http://127.0.0.1:8000
   ```

2. Complete setup in the browser at `$BASE/setup` and copy the Admin Token.

3. Seed demo data:
   ```bash
   curl "$BASE/dev/seed" -H "X-Admin-Token: <ADMIN_TOKEN>"
   ```

4. Generate PKCE (or generate in your app):
   ```bash
   curl "$BASE/dev/pkce" -H "X-Admin-Token: <ADMIN_TOKEN>"
   # copy code_verifier and code_challenge
   ```

5. Authorize in a browser (replace CHALLENGE):
   ```
   $BASE/authorize?client_id=demo-web&response_type=code&scope=openid%20profile%20email%20offline_access&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_challenge_method=S256&code_challenge=<CHALLENGE>
   ```

6. Exchange code for tokens:
   ```bash
   curl -X POST "$BASE/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d 'grant_type=authorization_code' \
        -d 'client_id=demo-web' \
        -d 'code_verifier=<VERIFIER>' \
        -d 'code=<CODE_FROM_CALLBACK>' \
        -d 'redirect_uri=http://localhost:3000/callback'
   ```

7. Call userinfo:
   ```bash
   curl "$BASE/userinfo" -H 'Authorization: Bearer <access_token>'
   ```

## Seed Demo Data (dev only)

Dev routes are disabled by default. To enable:

```bash
export ENABLE_DEV_ENDPOINTS=true
uv run server.py
```

Then, with your Admin Token from setup:

```bash
curl "$BASE/dev/seed" \
  -H "X-Admin-Token: <YOUR_SETUP_TOKEN>"
```

Seeds demo users (`alice/alice`, `bob/bob`) and a public client `demo-web` suitable for local demos.

## PKCE Helper (dev only)

When `ENABLE_DEV_ENDPOINTS=true`:

```bash
curl "$BASE/dev/pkce" \
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
   - Open Admin UI: `$BASE/admin/login` (use Admin Token).
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
     $BASE/authorize?
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
     curl -X POST "$BASE/token" \
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
     curl "$BASE/userinfo" \
          -H 'Authorization: Bearer <access_token>'
     ```

6. **Refresh the access token**
   - Example with curl:
     ```bash
     curl -X POST "$BASE/token" \
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

---

## Token Revocation

Endpoint: `POST /revoke`

Form params:
- `token`: the token string (access or refresh)
- `token_type_hint`: `access_token` or `refresh_token` (optional)

Client authentication options:
- `client_secret_basic` (recommended for confidential clients):
  ```bash
  curl -X POST "$BASE/revoke" \
       -u 'CLIENT_ID:CLIENT_SECRET' \
       -d 'token=<ACCESS_OR_REFRESH_TOKEN>' \
       -d 'token_type_hint=access_token'
  ```
- `client_secret_post`:
  ```bash
  curl -X POST "$BASE/revoke" \
       -d 'client_id=CLIENT_ID' \
       -d 'client_secret=CLIENT_SECRET' \
       -d 'token=<ACCESS_OR_REFRESH_TOKEN>' \
       -d 'token_type_hint=refresh_token'
  ```
- Public clients (no secret) are allowed by this demo for convenience:
  ```bash
  curl -X POST "$BASE/revoke" \
       -d 'client_id=PUBLIC_CLIENT_ID' \
       -d 'token=<ACCESS_OR_REFRESH_TOKEN>'
  ```

Per RFC7009, the endpoint returns 200 even if the token is unknown.

## Token Introspection

Endpoint: `POST /introspect`

Form params:
- `token`: the token string (access or refresh)
- `token_type_hint`: `access_token` or `refresh_token` (optional)

Examples:
- `client_secret_basic`:
  ```bash
  curl -X POST "$BASE/introspect" \
       -u 'CLIENT_ID:CLIENT_SECRET' \
       -d 'token=<ACCESS_OR_REFRESH_TOKEN>'
  ```
- `client_secret_post`:
  ```bash
  curl -X POST "$BASE/introspect" \
       -d 'client_id=CLIENT_ID' \
       -d 'client_secret=CLIENT_SECRET' \
       -d 'token=<ACCESS_OR_REFRESH_TOKEN>'
  ```
- Public client:
  ```bash
  curl -X POST "$BASE/introspect" \
       -d 'client_id=PUBLIC_CLIENT_ID' \
       -d 'token=<ACCESS_OR_REFRESH_TOKEN>'
  ```

Response example:
```json
{
  "active": true,
  "client_id": "demo-web",
  "token_type": "Bearer",
  "scope": "openid profile email",
  "exp": 1735689600,
  "iat": 1735686000,
  "sub": "1",
  "username": "alice"
}
```

---

## Logout Flow

Two options are provided:

- RP-initiated logout: `GET /logout`
  - Params: `client_id` or `id_token_hint`, optional `post_logout_redirect_uri`, `state`
  - The server revokes this user’s tokens for the given client (best-effort demo) and clears the session, then redirects if allowed by the client policy.
  - Example:
    ```bash
    curl "$BASE/logout?client_id=demo-web&post_logout_redirect_uri=http://localhost:3000/&state=bye"
    ```

- OIDC end session: `GET /end_session`
  - Params: `post_logout_redirect_uri`, optional `state`
  - Clears the session and optionally redirects.
  - Example:
    ```bash
    curl "$BASE/end_session?post_logout_redirect_uri=http://localhost:3000/&state=bye"
    ```

---

## Admin APIs

All Admin APIs require `X-Admin-Token` header (use the token created at `/setup`).

- Rotate signing key:
  ```bash
  curl -X POST "$BASE/admin/rotate_jwk" -H "X-Admin-Token: <ADMIN_TOKEN>"
  ```

- List or upsert scopes:
  ```bash
  curl "$BASE/admin/scopes" -H "X-Admin-Token: <ADMIN_TOKEN>"
  curl -X POST "$BASE/admin/scopes" -H "X-Admin-Token: <ADMIN_TOKEN>" \
       -H 'Content-Type: application/json' \
       -d '{"name":"files.read","description":"Read your files","claims":["files"]}'
  ```

- Delete a scope:
  ```bash
  curl -X DELETE "$BASE/admin/scopes/files.read" -H "X-Admin-Token: <ADMIN_TOKEN>"
  ```

- Get/update client policy:
  ```bash
  curl "$BASE/admin/clients/demo-web/policy" -H "X-Admin-Token: <ADMIN_TOKEN>"
  curl -X POST "$BASE/admin/clients/demo-web/policy" -H "X-Admin-Token: <ADMIN_TOKEN>" \
       -H 'Content-Type: application/json' \
       -d '{
             "allowed_scopes":"openid profile email offline_access",
             "default_scopes":"openid profile email",
             "post_logout_redirect_uris":"http://localhost:3000/",
             "require_pkce": true,
             "consent_policy":"once",
             "access_token_lifetime":3600,
             "refresh_token_ttl_days":30,
             "token_format":"opaque"
           }'
  ```

---

## Issuer and Discovery

- Discovery document: `GET /.well-known/openid-configuration`
  - Contains `issuer`, endpoint URLs, `jwks_uri`, supported scopes and methods.
  - Example:
    ```bash
    curl "$BASE/.well-known/openid-configuration"
    ```
- JWKS: `GET /.well-known/jwks.json`
  - Use to validate `id_token` (RS256) and JWT access tokens if enabled.

---

## Token Formats

- `id_token` (RS256) is returned when `openid` scope is requested.
- Access tokens are `opaque` by default; can be switched to `jwt` per client policy.
- Opaque tokens require introspection for validation; JWTs are self-contained and validated with JWKS.

---

## Troubleshooting (expanded)

- **[invalid_client at /token]** Ensure the client uses the correct auth method (`none`, `client_secret_post`, or `client_secret_basic`) matching its configuration.
- **[invalid_grant]** Code reused/expired or the `redirect_uri` at the token request doesn’t match the original authorize request.
- **[invalid_scope]** Requested scopes not in the client’s allowed set (policy). Adjust policy or request.
- **[insufficient_scope]** Accessing a protected API without the required scope.
- **[PKCE mismatch]** `code_verifier` must match the `code_challenge` sent to `/authorize`.
- **[Issuer mismatch]** Clients validating `id_token` must use the `issuer` from discovery.

---

## Production Deployment

- Example (gunicorn):
  ```bash
  pip install gunicorn
  gunicorn -w 4 -b 0.0.0.0:8000 server:app
  ```
- Place behind TLS-terminating proxy (nginx/ALB). Ensure consistent external URL so `issuer` is stable.
- Use Postgres/MySQL with pooling (set `DATABASE_URL`).
- Back up DB regularly (contains keys, settings).

---

## Security Checklist

- Replace demo login with your auth; add CSRF protection to admin forms.
- Use strong `APP_SECRET`; store secrets securely.
- Enforce strict `redirect_uris`; avoid wildcards.
- Enable rate limiting and monitoring.
- Rotate signing keys periodically.

---

## Client Types

- **Public (SPA/native)**: `token_endpoint_auth_method=none`, PKCE required, no client secret.
- **Confidential (server-side)**: `client_secret_post` or `client_secret_basic`, secret stored server-side.

---

## Examples

- `todo_demo.py`: simple SPA-style OAuth code flow with PKCE.
- `camera_demo.py`: similar flow with file access scopes.

---

## FAQ

- **Where is the Admin Token?** Created at `/setup` on first run; shown once and stored hashed. Use it for Admin UI and `X-Admin-Token`.
- **Dev helpers not working?** Set `ENABLE_DEV_ENDPOINTS=true` and include `X-Admin-Token`.
- **How do I change ports?** The server binds to 127.0.0.1:8000. To change, edit `server.py` (startup block) or run behind a reverse proxy/app server (e.g., gunicorn/nginx) on your desired port.
- **Why no ID token?** Include `openid` in the requested scope.
- **How to reset Admin Token?** Update `server_settings.admin_token_hash` in DB (or reinit DB for dev).


---
-

## Admin UI Reference

Use this section as an in-app guide from the Admin UI. The info icons on forms link to each subsection below.

### Overview

- **Dashboard**: `/admin/ui` shows quick links to Scopes, Clients, and Signing Keys.
- **Docs**: GitHub docs: https://github.com/Sbussiso/LOauth2#admin-ui-reference

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

