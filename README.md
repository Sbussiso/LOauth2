# Minimal OAuth2 Authorization Server

A production-ready OAuth 2.0 / OIDC Authorization Server built with Flask and Authlib.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Quick Start

```bash
# Install and run
export ENABLE_DEV_ENDPOINTS=true
uv run server.py

# Complete setup at http://127.0.0.1:8000/setup
# Seed demo data
curl http://127.0.0.1:8000/dev/seed -H "X-Admin-Token: <YOUR_TOKEN>"

# Run demo app
uv run todo_demo.py
# Open http://localhost:3000
```

---

## 📖 Documentation

### Getting Started
- **[Installation & Setup](#installation)** - Get up and running in 60 seconds
- **[Configuration](#configuration)** - Environment variables and setup options
- **[OAuth2 Flow Guide](#oauth2-flow-step-by-step)** - Complete authorization code flow walkthrough

### For Developers
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Common errors and solutions ⚠️ **Start here if you get errors!**
- **[Client Examples](docs/CLIENT_EXAMPLES.md)** - Complete working code examples with PKCE
- **[API Reference](docs/API_REFERENCE.md)** - All endpoints, parameters, and data models
- **[Admin UI Guide](docs/ADMIN_UI_GUIDE.md)** - Configure clients, scopes, and policies

### Advanced Topics
- **[Production Deployment](#production-deployment)** - Gunicorn, database, and TLS setup
- **[Security Checklist](#security-checklist)** - Best practices for production

---

## 🎯 Features

- ✅ **OIDC-ready**: Discovery, JWKS, UserInfo, ID tokens (RS256)
- ✅ **Authorization Code + PKCE (S256)** - Industry-standard secure flow
- ✅ **Consent Management** - Per-client policies (`always` | `once` | `skip`)
- ✅ **Refresh Token Rotation** - Enhanced security with automatic rotation
- ✅ **Flexible Scopes** - Define custom scopes with claims (no hardcoding)
- ✅ **Admin Web UI** - Manage clients, scopes, policies, and keys
- ✅ **Admin APIs** - Automate configuration with REST APIs
- ✅ **Dev Helpers** - Seed data, PKCE generator, quick client creation

**Stack**: Flask • Authlib • SQLAlchemy • SQLite (or PostgreSQL/MySQL)

---

## 📋 Requirements

- Python 3.10+
- pip or [uv](https://docs.astral.sh/uv/) (recommended)

---

## 🔧 Installation

### Using uv (recommended)
```bash
uv run server.py
```

### Using pip
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install flask authlib sqlalchemy
python server.py
```

Server starts at **http://127.0.0.1:8000** (fixed)

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_SECRET` | Flask session secret | Random (dev only) |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///oauth.db` |
| `ENABLE_DEV_ENDPOINTS` | Enable `/dev/*` routes | `false` |
| `ADMIN_TOKEN` | Bootstrap admin token (first-time only) | Generated at setup |

### Database Setup

SQLite (default):
```bash
# Database file created automatically at ./oauth.db
uv run server.py
```

PostgreSQL/MySQL:
```bash
export DATABASE_URL="postgresql://user:pass@localhost/oauth"
uv run server.py
```

---

## 🎬 Quickstart (60 seconds)

1. **Start server with dev endpoints**
   ```bash
   export ENABLE_DEV_ENDPOINTS=true
   uv run server.py
   export BASE=http://127.0.0.1:8000
   ```

2. **Complete first-time setup**
   - Open `$BASE/setup` in browser
   - Copy the Admin Token (shown once)

3. **Seed demo data**
   ```bash
   curl "$BASE/dev/seed" -H "X-Admin-Token: <ADMIN_TOKEN>"
   # Creates users: alice/alice, bob/bob
   # Creates client: demo-web
   ```

4. **Generate PKCE** (or use your app's implementation)
   ```bash
   curl "$BASE/dev/pkce" -H "X-Admin-Token: <ADMIN_TOKEN>"
   # Returns: code_verifier, code_challenge
   ```

5. **Authorize in browser** (replace `<CHALLENGE>`)
   ```
   $BASE/authorize?client_id=demo-web&response_type=code&scope=openid%20profile%20email%20offline_access&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_challenge_method=S256&code_challenge=<CHALLENGE>
   ```

6. **Exchange code for tokens**
   ```bash
   curl -X POST "$BASE/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d 'grant_type=authorization_code' \
        -d 'client_id=demo-web' \
        -d 'code_verifier=<VERIFIER>' \
        -d 'code=<CODE_FROM_CALLBACK>' \
        -d 'redirect_uri=http://localhost:3000/callback'
   ```

7. **Call UserInfo**
   ```bash
   curl "$BASE/userinfo" -H 'Authorization: Bearer <access_token>'
   ```

---

## 🔄 OAuth2 Flow (Step-by-Step)

<a name="oauth2-flow-step-by-step"></a>

### 1. Create a Client

Open Admin UI: `$BASE/admin/login` (use Admin Token)

Configure:
- **Redirect URI**: `http://localhost:3000/callback`
- **Grant types**: `authorization_code refresh_token`
- **Response types**: `code`
- **Scope**: `openid profile email offline_access`
- **Public client**: ✅ (enables PKCE requirement)

### 2. Generate PKCE (for public clients)

```bash
curl "$BASE/dev/pkce" -H "X-Admin-Token: <TOKEN>"
```

Or implement in your app (see [Client Examples](docs/CLIENT_EXAMPLES.md))

### 3. Authorization Request

Open in browser:
```
$BASE/authorize?
  client_id=demo-web&
  response_type=code&
  scope=openid%20profile%20email%20offline_access&
  redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&
  code_challenge_method=S256&
  code_challenge=<CHALLENGE>
```

- Login as `alice/alice`
- Approve consent
- Redirected to callback with `?code=...`

### 4. Exchange Code for Tokens

```bash
curl -X POST "$BASE/token" \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'grant_type=authorization_code' \
     -d 'client_id=demo-web' \
     -d 'code_verifier=<VERIFIER>' \
     -d 'code=<CODE>' \
     -d 'redirect_uri=http://localhost:3000/callback'
```

Response:
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "id_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email offline_access"
}
```

### 5. Call Protected APIs

```bash
curl "$BASE/userinfo" -H 'Authorization: Bearer <access_token>'
```

### 6. Refresh Access Token

```bash
curl -X POST "$BASE/token" \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'grant_type=refresh_token' \
     -d 'client_id=demo-web' \
     -d 'refresh_token=<REFRESH_TOKEN>'
```

Refresh tokens are rotated (old token revoked, new token issued).

---

## 🚨 Troubleshooting

<a name="troubleshooting"></a>

### Quick Fixes

**❌ 401 error at `/token`?**
1. Missing `client_secret`? → Check if your client is confidential, [add the secret](docs/TROUBLESHOOTING.md#-401-unauthorized-at-token)
2. Missing PKCE? → [Implement code_challenge/code_verifier](docs/TROUBLESHOOTING.md#-401-unauthorized-at-token)
3. Wrong `redirect_uri`? → Must match exactly in authorize & token requests

**❌ Invalid state or session lost?**
- [Use the stateless approach](docs/CLIENT_EXAMPLES.md#example-2-stateless-oauth2-embedding-pkce-in-state) (embed verifier in signed state)

**❌ Still stuck?**
- Read the full **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** 📕
- Compare with working `todo_demo.py`
- Check [Client Examples](docs/CLIENT_EXAMPLES.md) for correct implementation

---

## 📚 Examples

### Demo Applications

- **`todo_demo.py`**: Complete SPA OAuth flow with PKCE
- **`camera_demo.py`**: OAuth with custom scopes

```bash
# Run demo
uv run todo_demo.py
# Open http://localhost:3000
```

### Code Examples

See **[Client Examples](docs/CLIENT_EXAMPLES.md)** for:
- Basic OAuth2 client with PKCE
- Stateless OAuth2 (signed state)
- Session vs stateless approaches

---

## 🔐 Security Checklist

<a name="security-checklist"></a>

- [ ] Replace demo login with production auth (e.g., LDAP, SAML)
- [ ] Use strong, random `APP_SECRET` (32+ bytes)
- [ ] Store secrets in environment variables or secret manager
- [ ] Enforce strict `redirect_uris` (no wildcards)
- [ ] Enable PKCE for all public clients
- [ ] Use `client_secret_basic` for confidential clients
- [ ] Enable rate limiting on `/token` and `/authorize`
- [ ] Set up monitoring and alerting
- [ ] Rotate signing keys periodically (see [Admin UI](docs/ADMIN_UI_GUIDE.md))
- [ ] Use HTTPS in production (TLS termination at proxy)
- [ ] Regular database backups

---

## 🚀 Production Deployment

<a name="production-deployment"></a>

### Using Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 server:app
```

### Using Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "server:app"]
```

### Production Checklist

- [ ] Use PostgreSQL or MySQL (not SQLite)
- [ ] Configure connection pooling
- [ ] Set up reverse proxy (nginx, ALB) with TLS
- [ ] Ensure consistent external URL (stable `issuer`)
- [ ] Enable database backups
- [ ] Set up log aggregation
- [ ] Configure health checks
- [ ] Use environment-based secrets management

---

## 🛠️ Client Types

| Type | Auth Method | Secret | PKCE | Use Case |
|------|-------------|--------|------|----------|
| **Public** | `none` | ❌ | ✅ Required | SPAs, mobile apps, native apps |
| **Confidential** | `client_secret_post`<br>`client_secret_basic` | ✅ Required | ⚠️ Optional | Backend services, server-side apps |

---

## ❓ FAQ

<details>
<summary><strong>Where is the Admin Token?</strong></summary>

Created at `/setup` on first run. Shown once, then stored hashed. Use it for Admin UI and API access.
</details>

<details>
<summary><strong>Dev helpers not working?</strong></summary>

Set `ENABLE_DEV_ENDPOINTS=true` and include `X-Admin-Token` header.
</details>

<details>
<summary><strong>How do I change ports?</strong></summary>

Edit `server.py` (startup block) or use gunicorn/nginx with desired port.
</details>

<details>
<summary><strong>Why no ID token?</strong></summary>

Include `openid` in the requested `scope`.
</details>

<details>
<summary><strong>How to reset Admin Token?</strong></summary>

Update `server_settings.admin_token_hash` in DB (or reinit DB for dev).
</details>

<details>
<summary><strong>Getting 401 during token exchange?</strong></summary>

See [Troubleshooting Guide](docs/TROUBLESHOOTING.md#-401-unauthorized-at-token). Most common: missing `client_secret` or PKCE.
</details>

---

## 📄 License

MIT

---

## 🔗 Additional Resources

- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Solve common integration issues
- [Client Examples](docs/CLIENT_EXAMPLES.md) - Working code with PKCE
- [API Reference](docs/API_REFERENCE.md) - Complete endpoint documentation
- [Admin UI Guide](docs/ADMIN_UI_GUIDE.md) - Manage your OAuth2 server

---

**Built with ❤️ using Flask, Authlib, and SQLAlchemy**
