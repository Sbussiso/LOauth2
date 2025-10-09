# Admin UI Reference

Use this guide to understand all fields and options in the Admin UI.

## Overview

- **Dashboard**: `/admin/ui` shows quick links to Scopes, Users, Clients, and Signing Keys
- **Login**: `/admin/login` requires the Admin Token created during first-time setup
- **GitHub Docs**: https://github.com/Sbussiso/LOauth2#admin-ui-reference

## Managing Users

Create, update, and delete local users used to authenticate on the Authorization Server.

### User List

- Path: `/admin/ui/users`
- Shows ID, Username, Email
- Actions: Edit, Delete (deletes tokens, auth codes, and remembered consents for the user)

### Create User

- Path: `/admin/ui/users/new`
- Fields:
  - Username (required, unique)
  - Email (optional)
  - Password (required)

### Edit User

- Path: `/admin/ui/users/<id>`
- Actions:
  - Update Email
  - Set New Password (leave blank to keep existing)
  - Revoke All Tokens (forces re-login on all clients)

### Delete User

- Path: POST `/admin/ui/users/delete`
- Effect: Removes the user and cleans up related data (tokens, auth codes, remembered consents)

## Managing Clients

Create and manage OAuth2/OIDC clients that integrate with this Authorization Server.

### Step-by-step: Create a Client (Beginner Friendly)

1. Open the Admin UI
   - Visit `http://127.0.0.1:8000/admin/login`
   - Enter your Admin Token (created during `/setup`)

2. Go to Clients
   - Click `Clients` on the dashboard (`/admin/ui`)
   - Click `Create Client` (or `New`)

3. Fill in basic client info
   - Client ID: short, URL-safe name (e.g., `my-app`)
   - Client Name: shown on consent screens (e.g., `My App`)
   - Redirect URIs: exact callback URLs (space-separated)
     - Examples:
       - `http://localhost:3000/callback`
       - `http://127.0.0.1:3000/callback`
     - Must match exactly what your app sends in `redirect_uri`

4. Choose client type and auth method
   - Public client (SPA/mobile): set Token Endpoint Auth Method to `none`
   - Confidential client (backend): choose `client_secret_post` or `client_secret_basic`
   - If confidential, copy the generated client secret after saving

5. Select grants/response types
   - Grant Types: usually `authorization_code refresh_token`
   - Response Types: `code`

6. Set requested scopes
   - Scope: `openid profile email offline_access`
   - You can add custom scopes later in `Scopes`

7. Configure Client Policy (important)
   - Allowed Scopes: must include all scopes your app may request
   - Default Scopes: auto-applied if your app omits `scope`
   - Require PKCE: turn ON for public clients (recommended)
   - Consent Policy: `once` (remember user consent) is a good default
   - Token Lifetimes: keep defaults for first setup

8. Save and test
   - Save the client
   - If dev helpers are enabled (`ENABLE_DEV_ENDPOINTS=true`), you can generate PKCE at `/dev/pkce` for quick testing
   - Build the `/authorize` URL in your app and try the full flow

### Client Fields

#### Client ID
- Unique identifier for the client
- Use a simple, stable, URL-safe value
- Examples: `my-app`, `camera-web`, `todo-spa`

#### Client Name
- Human-readable name shown on consent screens
- Example: `My Camera App`

#### Redirect URIs
- Space- or newline-separated list of exact callback URLs
- Must match the `redirect_uri` in authorize/token requests exactly
- Examples:
  - `http://localhost:3000/callback`
  - `https://myapp.example.com/auth/callback`

#### Client Scope
- Space-separated scopes the client will request
- Common: `openid profile email offline_access`
- Must also be allowed by the client policy (see Allowed Scopes below)

#### Grant Types
- OAuth2 flows permitted for this client
- Common: `authorization_code refresh_token`
- Public clients (SPAs/native) should use Authorization Code with PKCE

#### Response Types
- Authorization response modes
- Commonly `code`

#### Client Type
- **Public clients**: No client secret; must use PKCE (recommended for SPAs/native)
- **Confidential clients**: Server-side apps that keep a client secret; choose an auth method

#### Token Endpoint Auth Method
- How confidential clients authenticate at `/token`
- Options:
  - `none` (public client)
  - `client_secret_post` (send secret in POST body)
  - `client_secret_basic` (send secret in HTTP Basic Auth header)

#### Require Consent
- If enabled, the user must approve on the consent screen before tokens are issued
- Use together with the Client Policy's Consent Policy (below) to control how often consent is shown

### Client Policy

#### Allowed Scopes
- Space-separated list of scopes this client is permitted to request
- Requests outside this set will be rejected

#### Default Scopes
- Scopes automatically applied when an authorize request does not specify `scope`

#### Post-Logout Redirect URIs
- Space-separated list of URLs users may be redirected to after logout
- Used by `GET /end_session`

#### Require PKCE
- Enforces PKCE S256 for Authorization Code flow
- Strongly recommended for public clients

#### Consent Policy
- Controls consent prompting:
  - `always`: ask every time
  - `once`: remember consent per user+client+scope
  - `skip`: never show consent screen

#### Access Token Lifetime (seconds)
- How long access tokens remain valid
- Typical production default: `3600` (1 hour)

#### Refresh Token TTL (days)
- How long refresh tokens remain valid
- Tokens are rotated on use

#### Token Format
- `opaque` (default): access token is a reference stored server-side
- `jwt` (optional): self-contained access token signed by the server (verify via JWKS)

## Managing Scopes

Define scopes (name, description, claims) in `/admin/ui/scopes`.

- Scopes appear on consent screens with their descriptions
- Claims listed on a scope can be used to derive ID token or UserInfo content per your implementation

### Scope Fields

#### Scope Name
- Unique identifier for the scope
- Examples: `openid`, `profile`, `email`, `files.read`

#### Description
- Human-readable description shown on consent screen
- Example: "Access your basic profile information"

#### Claims
- Space-separated list of claims associated with this scope
- Used to populate ID tokens and UserInfo responses
- Examples: `name email picture`, `sub preferred_username`

## Managing Signing Keys

Manage and rotate RS256 signing keys in `/admin/ui/keys`.

- JWKS is published at `/.well-known/jwks.json`
- Rotating keys preserves old keys to validate historical tokens
- Each key has a unique Key ID (kid) used in JWT headers

### Key Rotation

1. Click "Rotate Key" to generate a new signing key
2. Old keys remain available for token verification
3. New tokens will be signed with the new key
4. Old tokens remain valid until expiration

## First-time Setup

On first run, visit `/setup` to initialize the server:

1. System generates a random Admin Token
2. Token is shown **once only** (copy it immediately)
3. Token is hashed and stored in the database
4. Use this token for:
   - Admin UI login (`/admin/login`)
   - Admin API requests (`X-Admin-Token` header)

**Important**: Keep your Admin Token secure. If lost, you'll need to reset it via database access.

## Dev Endpoints

Disabled by default. Set `ENABLE_DEV_ENDPOINTS=true` to enable:

- `GET /dev/seed` - Create demo users and clients
- `GET /dev/pkce` - Generate PKCE verifier/challenge

Dev endpoints still require `X-Admin-Token` when enabled.

---

[← Back to Main README](../README.md)
