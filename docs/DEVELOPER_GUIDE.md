# Developer Guide: Building Apps with LOauth2

Use this guide to integrate your applications (web, backend, native) with your self‑hosted LOauth2 Authorization Server.

## Overview

- Base URL: `http://127.0.0.1:8000` (adjust for your deployment)
- Discovery: `GET /.well-known/openid-configuration`
- Core endpoints:
  - `GET/POST /authorize`
  - `POST /token`
  - `GET /userinfo`
  - `POST /revoke`, `POST /introspect`
- Grants supported:
  - Authorization Code with PKCE (recommended)
  - Refresh Token

## 1) Register a Client

Use `Admin UI → Clients` to register your application.

- Client Type:
  - Public (SPAs, native/mobile): `token_endpoint_auth_method = none`, Require PKCE
  - Confidential (server-side): `client_secret_post` or `client_secret_basic`
- Redirect URIs: add exact callback URL(s)
- Scope: e.g. `openid profile email offline_access`
- Client Policy:
  - Allowed Scopes: union of scopes your app may request
  - Default Scopes: applied when the request omits `scope`
  - Require PKCE: enable for public clients
  - Consent Policy: `always | once | skip`

## 2) Authorization Code Flow (Backend Web App)

Recommended pattern for traditional web apps: exchange the authorization code on your backend.

### Steps

1. Generate PKCE (optional for confidential clients; recommended if policy requires it)
2. Redirect user to `/authorize`
3. Handle callback with `?code=...&state=...`
4. POST to `/token` to exchange code for tokens
5. Store tokens securely server‑side (session or database)
6. Call `/userinfo` or your APIs with `Authorization: Bearer <access_token>`

### Python (Flask) example

```python
import os, base64, hashlib, secrets
import requests
from flask import Flask, session, redirect, request, url_for
from urllib.parse import urlencode

BASE = os.environ.get('AUTH_BASE', 'http://127.0.0.1:8000')
CLIENT_ID = os.environ.get('CLIENT_ID', 'your-client-id')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')  # for confidential clients
REDIRECT_URI = os.environ.get('REDIRECT_URI', 'http://localhost:3000/callback')
SCOPE = 'openid profile email offline_access'

app = Flask(__name__)
app.secret_key = os.urandom(24)

def gen_pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip('=')
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    return verifier, challenge

@app.route('/login')
def login():
    v, c = gen_pkce()
    session['code_verifier'] = v
    state = secrets.token_urlsafe(24)
    session['state'] = state
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'state': state,
        'code_challenge_method': 'S256',
        'code_challenge': c,
    }
    return redirect(f"{BASE}/authorize?" + urlencode(params))

@app.route('/callback')
def callback():
    if request.args.get('state') != session.get('state'):
        return 'Invalid state', 400
    code = request.args.get('code')
    data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': session.get('code_verifier'),
    }
    if CLIENT_SECRET:  # confidential clients
        data['client_secret'] = CLIENT_SECRET
    r = requests.post(f"{BASE}/token", data=data)
    if r.status_code != 200:
        return f"Token exchange failed: {r.status_code} {r.text}", 502
    session['tokens'] = r.json()
    return redirect(url_for('me'))

@app.route('/me')
def me():
    tokens = session.get('tokens')
    if not tokens: return redirect(url_for('login'))
    r = requests.get(f"{BASE}/userinfo", headers={'Authorization': 'Bearer ' + tokens['access_token']})
    return r.json(), r.status_code
```

## 3) SPA Pattern (Browser Frontend)

Use a Back‑End‑for‑Front‑End (BFF) to perform the token exchange on your server and set an HTTP‑only session cookie for the browser. This avoids exposing refresh tokens to the browser and avoids CORS issues at `/token`.

If you still need a pure SPA token exchange, ensure your deployment allows cross‑origin requests to `/token` (CORS) and store tokens securely in memory.

Minimal browser steps (conceptual):

```js
// 1) Generate PKCE (verifier, challenge)
// 2) Redirect to /authorize with code_challenge
// 3) On callback, POST code + code_verifier to your backend, not directly to /token
```

## 4) Native/Mobile Apps

Use a standard OAuth2/OIDC client library that supports PKCE and Authorization Code flow. Configure:

- Authorization endpoint: from discovery
- Token endpoint: from discovery
- Client ID: your registered client
- Redirect URI: app‑specific (custom scheme or loopback)

## 5) Using Tokens

- Access token: send as `Authorization: Bearer <access_token>`
- Refresh token: securely store and use to obtain new access tokens via `grant_type=refresh_token`
- ID token: present when `openid` scope is included (JWT, RS256). Verify signature and `iss`, `aud`, `exp` using `/.well-known/jwks.json` and discovery `issuer`.

Refresh example (Python):

```python
r = requests.post(f"{BASE}/token", data={
    'grant_type': 'refresh_token',
    'client_id': CLIENT_ID,
    'refresh_token': tokens['refresh_token'],
})
new_tokens = r.json()
```

## 6) Protecting Your APIs

If your resource server needs to validate opaque access tokens, call `/introspect`:

```bash
curl -X POST "$BASE/introspect" \
     -d 'client_id=YOUR_CLIENT_ID' \
     -d 'token=ACCESS_TOKEN'
```

Check `active: true` and enforce required scopes. For JWT access tokens (if configured), validate with JWKS.

## 7) Logout

- RP‑initiated logout: `GET /logout?client_id=...&post_logout_redirect_uri=...`
- OIDC end session: `GET /end_session`

## 8) Scopes and Consent

- Request only what you need. Common: `openid profile email`.
- Include `offline_access` to obtain a refresh token (subject to client policy).
- Consent display and remembering are controlled by client policy (`consent_policy`).

## 9) Discovery (Dynamic Configuration)

Fetch the OIDC discovery document to discover endpoints and capabilities:

```bash
curl $BASE/.well-known/openid-configuration | jq
```

Key fields:
- `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`.

## 10) Common Pitfalls

- **Exact redirect_uri match**: Must match what you registered.
- **PKCE**: If policy requires PKCE, include `code_challenge` (S256) and send `code_verifier` to `/token`.
- **State**: Always send and verify `state` to prevent CSRF.
- **Scopes**: Requests must be within the client's Allowed Scopes, or you'll get `invalid_scope`.
- **Token storage**: Never store refresh tokens in browser localStorage. Prefer HTTP‑only cookies via BFF.

## 11) Helpful Tools

- Dev helpers (optional):
  - `GET /dev/seed` (creates demo users/clients)
  - `GET /dev/pkce` (generate verifier/challenge)
- Admin APIs (token required):
  - `GET/POST /admin/users` (list/create users)
  - `GET/DELETE /admin/users/<id>` (manage users)

---

For more: see `docs/CLIENT_EXAMPLES.md`, `docs/TROUBLESHOOTING.md`, and `docs/API_REFERENCE.md`.
