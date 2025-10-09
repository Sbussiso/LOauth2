# API Reference

## Endpoints

### OIDC Discovery
- **`GET /.well-known/openid-configuration`** - OpenID Connect discovery document
- **`GET /.well-known/jwks.json`** - JSON Web Key Set for token validation

### OAuth2 Core Endpoints
- **`GET/POST /authorize`** - Authorization endpoint
- **`POST /token`** - Token endpoint (access token, refresh token exchange)
- **`GET /userinfo`** - UserInfo endpoint (requires valid access token)
- **`POST /revoke`** - Token revocation endpoint
- **`POST /introspect`** - Token introspection endpoint

### Session & Logout
- **`GET /logout`** - RP-initiated logout
- **`GET /end_session`** - OIDC end session endpoint

### Admin UI
- **`GET /admin/login`** - Admin UI login page
- **`GET /admin/ui`** - Admin dashboard
- **`GET/POST /admin/ui/scopes`** - Manage scopes
- **`GET /admin/ui/users`** - List users
- **`GET/POST /admin/ui/users/new`** - Create user
- **`GET/POST /admin/ui/users/<id>`** - Edit user (email/password, revoke tokens)
- **`POST /admin/ui/users/delete`** - Delete user (with cleanup)
- **`GET/POST /admin/ui/clients`** - Manage clients
- **`GET/POST /admin/ui/clients/<client_id>`** - Edit specific client
- **`GET/POST /admin/ui/keys`** - Manage signing keys

### Admin APIs
All Admin APIs require `X-Admin-Token` header.

- **`GET/POST /admin/scopes`** - List or upsert scopes
- **`DELETE /admin/scopes/<name>`** - Delete a scope
- **`GET/POST /admin/clients/<client_id>/policy`** - Get/update client policy
- **`POST /admin/rotate_jwk`** - Rotate signing key

### Dev Endpoints (Optional)
Requires `ENABLE_DEV_ENDPOINTS=true` and `X-Admin-Token`.

- **`GET /dev/seed`** - Seed demo data (users, clients)
- **`POST /dev/create_client`** - Quick client creation
- **`GET /dev/pkce`** - Generate PKCE verifier/challenge pair

### Health
- **`GET /health`** - Health probe (returns `{ "status": "ok" }`)

## Data Model

### User
```
id: integer (primary key)
username: string (unique)
password_hash: string
email: string
```

### OAuth2 Client
```
client_id: string (primary key)
client_secret: string (hashed)
grant_types: space-separated string
redirect_uris: space-separated string
response_types: space-separated string
scope: space-separated string
token_endpoint_auth_method: enum (none, client_secret_post, client_secret_basic)
require_consent: boolean
```

### OAuth2 Code
```
code: string (primary key)
client_id: string (foreign key)
user_id: integer (foreign key)
redirect_uri: string
scope: string
code_challenge: string (for PKCE)
code_challenge_method: string (S256)
expires_at: datetime
```

### OAuth2 Token
```
token: string (primary key)
client_id: string
user_id: integer
token_type: enum (Bearer, refresh_token)
scope: string
expires_at: datetime
revoked: boolean
```

## Token Revocation

Endpoint: `POST /revoke`

Form params:
- `token`: the token string (access or refresh)
- `token_type_hint`: `access_token` or `refresh_token` (optional)

Client authentication options:

**client_secret_basic** (recommended for confidential clients):
```bash
curl -X POST "$BASE/revoke" \
     -u 'CLIENT_ID:CLIENT_SECRET' \
     -d 'token=<ACCESS_OR_REFRESH_TOKEN>' \
     -d 'token_type_hint=access_token'
```

**client_secret_post**:
```bash
curl -X POST "$BASE/revoke" \
     -d 'client_id=CLIENT_ID' \
     -d 'client_secret=CLIENT_SECRET' \
     -d 'token=<ACCESS_OR_REFRESH_TOKEN>' \
     -d 'token_type_hint=refresh_token'
```

**Public clients** (no secret):
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

**client_secret_basic**:
```bash
curl -X POST "$BASE/introspect" \
     -u 'CLIENT_ID:CLIENT_SECRET' \
     -d 'token=<ACCESS_OR_REFRESH_TOKEN>'
```

**client_secret_post**:
```bash
curl -X POST "$BASE/introspect" \
     -d 'client_id=CLIENT_ID' \
     -d 'client_secret=CLIENT_SECRET' \
     -d 'token=<ACCESS_OR_REFRESH_TOKEN>'
```

**Public client**:
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

## Logout Flow

### RP-initiated logout
**`GET /logout`**

Params:
- `client_id` or `id_token_hint` (required)
- `post_logout_redirect_uri` (optional)
- `state` (optional)

The server revokes this user's tokens for the given client and clears the session, then redirects if allowed by the client policy.

Example:
```bash
curl "$BASE/logout?client_id=demo-web&post_logout_redirect_uri=http://localhost:3000/&state=bye"
```

### OIDC end session
**`GET /end_session`**

Params:
- `post_logout_redirect_uri` (optional)
- `state` (optional)

Clears the session and optionally redirects.

Example:
```bash
curl "$BASE/end_session?post_logout_redirect_uri=http://localhost:3000/&state=bye"
```

## Admin APIs

All Admin APIs require `X-Admin-Token` header (use the token created at `/setup`).

### Rotate Signing Key
```bash
curl -X POST "$BASE/admin/rotate_jwk" \
     -H "X-Admin-Token: <ADMIN_TOKEN>"
```

### Manage Scopes

**List scopes:**
```bash
curl "$BASE/admin/scopes" \
     -H "X-Admin-Token: <ADMIN_TOKEN>"
```

**Create/update scope:**
```bash
curl -X POST "$BASE/admin/scopes" \
     -H "X-Admin-Token: <ADMIN_TOKEN>" \
     -H 'Content-Type: application/json' \
     -d '{
       "name":"files.read",
       "description":"Read your files",
       "claims":["files"]
     }'
```

**Delete scope:**
```bash
curl -X DELETE "$BASE/admin/scopes/files.read" \
     -H "X-Admin-Token: <ADMIN_TOKEN>"
```

### Client Policy Management

**Get client policy:**
```bash
curl "$BASE/admin/clients/demo-web/policy" \
     -H "X-Admin-Token: <ADMIN_TOKEN>"
```

**Update client policy:**
```bash
curl -X POST "$BASE/admin/clients/demo-web/policy" \
     -H "X-Admin-Token: <ADMIN_TOKEN>" \
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

## Token Formats

- **`id_token`** (RS256): Returned when `openid` scope is requested
- **Access tokens**: `opaque` by default; can be switched to `jwt` per client policy
- **Opaque tokens**: Require introspection for validation
- **JWT tokens**: Self-contained and validated with JWKS

---

[← Back to Main README](../README.md)
