# Your OAuth2 Server. Your Rules. Your Data.

**A complete, self-hosted OAuth 2.0 / OIDC Authorization Server that you control.**

No third-party dependencies. No cloud providers. No data sharing.
Deploy it locally, own it completely, and never worry about external OAuth services again.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Self-Hosted](https://img.shields.io/badge/Self--Hosted-100%25-green.svg)](https://github.com/Sbussiso/LOauth2)

---

## 🔐 Why Self-Host Your OAuth2 Server?

### You Own Your Authentication
- **No vendor lock-in** - Your auth infrastructure, your control
- **Complete data privacy** - User credentials never leave your infrastructure
- **Zero external dependencies** - No Auth0, Okta, or cloud provider required
- **Unlimited users** - No per-user pricing or subscription fees

### Enterprise-Grade Security
- **Industry-standard protocols** - OAuth 2.0, OIDC, PKCE (S256)
- **Production-ready** - Used in real-world applications
- **Audit everything** - Full access to logs, tokens, and user activity
- **Custom policies** - Define your own consent flows and token lifetimes

### Total Flexibility
- **Deploy anywhere** - Local network, private cloud, or air-gapped environments
- **Customize everything** - Scopes, claims, token formats, consent screens
- **Integrate seamlessly** - Works with any OAuth2-compatible application
- **Scale on your terms** - From 10 users to 10,000+

---

## 🚀 Get Started in 60 Seconds

```bash
# Clone and run
git clone https://github.com/Sbussiso/LOauth2.git
cd LOauth2
export ENABLE_DEV_ENDPOINTS=true
uv run server.py

# Complete setup at http://127.0.0.1:8000/setup
# Your OAuth2 server is now running!
```

**That's it.** No accounts to create. No credit card required. No data sent to third parties.

---

## ⚡ Core Features

### 🔒 Security First
- ✅ **PKCE (S256)** - Protection against authorization code interception
- ✅ **Refresh Token Rotation** - Automatic token rotation for enhanced security
- ✅ **RS256 Signing Keys** - Industry-standard JWT signing with key rotation
- ✅ **Consent Management** - Granular user consent with configurable policies
- ✅ **Client Authentication** - Multiple auth methods (none, secret_post, secret_basic)

### 🎛️ Full Control
- ✅ **Admin Web UI** - Manage clients, scopes, policies, and keys through intuitive interface
- ✅ **Admin REST APIs** - Automate configuration and management
- ✅ **Custom Scopes** - Define your own scopes with descriptions and claims
- ✅ **Flexible Policies** - Per-client token lifetimes, consent rules, and formats
- ✅ **SQLite/PostgreSQL/MySQL** - Choose your database backend

### 🌐 Standards Compliant
- ✅ **OpenID Connect (OIDC)** - Full OIDC discovery, JWKS, UserInfo, ID tokens
- ✅ **OAuth 2.0** - Authorization Code, Refresh Token grants
- ✅ **Token Operations** - Revocation, introspection, refresh
- ✅ **Multiple Client Types** - Public (SPAs, mobile) and confidential (backend)

### 🛠️ Developer Friendly
- ✅ **Working Examples** - Complete demo apps included (todo, camera)
- ✅ **Dev Tools** - Seed data, PKCE generator, quick client creation
- ✅ **Comprehensive Docs** - Troubleshooting guides and code examples
- ✅ **Easy Integration** - Works with any OAuth2 client library

---

## 📖 Documentation

### 🚦 Getting Started
- **[Installation & Setup](#installation)** - Deploy in minutes
- **[Configuration](#configuration)** - Environment variables and database setup
- **[OAuth2 Flow Walkthrough](#oauth2-flow-step-by-step)** - Complete authorization guide

### 👨‍💻 For Developers
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Solve integration issues fast ⚠️
- **[Client Code Examples](docs/CLIENT_EXAMPLES.md)** - Working Python/Flask examples with PKCE
- **[API Reference](docs/API_REFERENCE.md)** - Complete endpoint documentation
- **[Admin UI Guide](docs/ADMIN_UI_GUIDE.md)** - Configure clients and policies
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Build apps with LOauth2 (flows, PKCE, BFF, tokens, examples)

### 🚀 Advanced
- **[Production Deployment](#production-deployment)** - Scale with Gunicorn, Docker, PostgreSQL
- **[Security Best Practices](#security-checklist)** - Harden your deployment

---

## LOauth2 vs. Cloud OAuth Providers

| Feature | Self-Hosted (This Project) | Auth0 / Okta / etc. |
|---------|---------------------------|---------------------|
| **Data Privacy** | ✅ 100% on your infrastructure | ❌ Data on their servers |
| **Cost** | ✅ Free (MIT License) | ❌ $$$+ per user/month |
| **Vendor Lock-in** | ✅ None | ❌ Tied to provider |
| **Customization** | ✅ Unlimited | ⚠️ Limited by their plans |
| **Network Requirements** | ✅ Works offline/air-gapped | ❌ Requires internet |
| **Control** | ✅ You own everything | ❌ Subject to their terms |
| **Audit & Compliance** | ✅ Full access to all data | ⚠️ Limited visibility |
| **Scalability** | ✅ Scale on your hardware | ⚠️ Pay for each tier |

---

## 🎯 Perfect For

- **🏢 Enterprise Teams** - Own your authentication without vendor fees
- **🔬 Research Labs** - Air-gapped or secure environments
- **🏠 Homelab Enthusiasts** - Self-host all your services with OAuth2
- **🚀 Startups** - Start free, scale without per-user costs
- **🛡️ Privacy-Focused Orgs** - Keep user data on your infrastructure
- **🎓 Education** - Learn OAuth2/OIDC with a real server

---

## 📋 Requirements

- Python 3.10+
- SQLite (included) or PostgreSQL/MySQL
- 512MB RAM minimum (scales with usage)

---

## 🔧 Installation

### Quick Start (SQLite)
```bash
# Using uv (recommended)
uv run server.py

# Using pip
python3 -m venv .venv
source .venv/bin/activate
pip install flask authlib sqlalchemy
python server.py
```

Server starts at **http://127.0.0.1:8000**

### Production Setup (PostgreSQL)
```bash
# Set database URL
export DATABASE_URL="postgresql://user:pass@localhost/oauth"
export APP_SECRET="your-secure-random-secret-key"

# Run with Gunicorn
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 server:app
```

### Docker Deployment
```bash
docker build -t oauth2-server .
docker run -p 8000:8000 \
  -e DATABASE_URL="sqlite:////data/oauth.db" \
  -e APP_SECRET="..." \
  -v oauth2_app_data:/data \
  oauth2-server
```

#### Docker Compose (SQLite-only)

```bash
# Optional: set a strong secret for sessions
export APP_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Build and start (no .env required)
docker compose up -d --build

# Then open http://127.0.0.1:8000/setup
```

- Compose defaults to `DATABASE_URL=sqlite:////data/oauth.db` and persists data in the `app_data` volume.
- To enable dev helpers (e.g. /dev/seed, /dev/pkce):
  ```bash
  export ENABLE_DEV_ENDPOINTS=true
  docker compose up -d
  ```
  Then seed:
  ```bash
  curl "http://127.0.0.1:8000/dev/seed?reset=1" -H "X-Admin-Token: <ADMIN_TOKEN>"
  ```

#### Where your data lives (Docker)

- SQLite data is stored inside the container at: `/data/oauth.db`.
- It is persisted via the named volume `app_data` in `docker-compose.yml`.
- The volume keeps your data when you stop/remove the container.
- To remove all data, including the volume:
  ```bash
  docker compose down -v   # WARNING: deletes volumes and your data
  ```


---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_SECRET` | Flask session secret (use strong random value) | Random (dev only) |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///oauth.db` |
| `ENABLE_DEV_ENDPOINTS` | Enable `/dev/*` helper routes | `false` |
| `ADMIN_TOKEN` | Bootstrap admin token (first-time setup only) | Generated at `/setup` |

### Database Options

**SQLite** (development/small deployments):
```bash
# Automatic - database file created at ./oauth.db
uv run server.py
```

**PostgreSQL** (recommended for production):
```bash
export DATABASE_URL="postgresql://user:password@host:5432/dbname"
uv run server.py
```

**MySQL/MariaDB**:
```bash
export DATABASE_URL="mysql+pymysql://user:password@host:3306/dbname"
pip install pymysql
uv run server.py
```

---

## 🎬 Quick Start Guide

### 1. Initial Setup (One Time)

```bash
export ENABLE_DEV_ENDPOINTS=true
uv run server.py
```

Open **http://127.0.0.1:8000/setup** in your browser:
- System generates a secure Admin Token
- **Copy it immediately** (shown only once)
- Token is hashed and stored in database
- Use it to access Admin UI and APIs

### 2. Seed Demo Data (Optional)

```bash
export BASE=http://127.0.0.1:8000
curl "$BASE/dev/seed" -H "X-Admin-Token: <YOUR_ADMIN_TOKEN>"
```

Creates:
- Demo users: `alice/alice`, `bob/bob`
- Demo client: `demo-web` (public, PKCE-enabled)
- Default scopes: `openid`, `profile`, `email`, `offline_access`

### 3. Test with Demo App

```bash
# Run the included todo demo
uv run todo_demo.py

# Open http://localhost:3000
# Sign in with alice/alice
```

**🎉 You now have a working OAuth2 server!**

---

## 🔄 OAuth2 Authorization Flow

<a name="oauth2-flow-step-by-step"></a>

### Complete Walkthrough

#### Step 1: Register Your Application

Access Admin UI at **http://127.0.0.1:8000/admin/login**

Create a new client:
```
Client ID: my-app
Redirect URI: http://localhost:3000/callback
Grant Types: authorization_code refresh_token
Response Types: code
Scope: openid profile email offline_access
Client Type: Public (for SPAs/mobile) or Confidential (for backends)
```

**For confidential clients**: Copy the generated `client_secret`

#### Step 2: Implement Authorization (Your App)

```python
# Generate PKCE
import os, base64, hashlib

verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
challenge = base64.urlsafe_b64encode(
    hashlib.sha256(verifier.encode()).digest()
).decode().rstrip("=")

# Redirect user to authorization endpoint
auth_url = (
    "http://127.0.0.1:8000/authorize?"
    "client_id=my-app&"
    "response_type=code&"
    "redirect_uri=http://localhost:3000/callback&"
    "scope=openid profile email offline_access&"
    "code_challenge_method=S256&"
    f"code_challenge={challenge}&"
    "state=random-state-value"
)
```

#### Step 3: Handle Callback

User approves consent → Redirected to your callback URL with `code`

```python
# Exchange code for tokens
response = requests.post(
    "http://127.0.0.1:8000/token",
    data={
        "grant_type": "authorization_code",
        "client_id": "my-app",
        "client_secret": "...",  # Only for confidential clients
        "code": code_from_callback,
        "redirect_uri": "http://localhost:3000/callback",
        "code_verifier": verifier,  # PKCE verifier
    }
)

tokens = response.json()
# {
#   "access_token": "...",
#   "refresh_token": "...",
#   "id_token": "...",
#   "token_type": "Bearer",
#   "expires_in": 3600
# }
```

#### Step 4: Access Protected Resources

```python
# Call UserInfo endpoint
response = requests.get(
    "http://127.0.0.1:8000/userinfo",
    headers={"Authorization": f"Bearer {access_token}"}
)

user_info = response.json()
# {
#   "sub": "1",
#   "preferred_username": "alice",
#   "email": "alice@example.com",
#   ...
# }
```

#### Step 5: Refresh Tokens (Optional)

```python
# When access token expires
response = requests.post(
    "http://127.0.0.1:8000/token",
    data={
        "grant_type": "refresh_token",
        "client_id": "my-app",
        "refresh_token": refresh_token,
    }
)

new_tokens = response.json()
# Old refresh_token is revoked, new one issued (rotation)
```

**📚 See [Client Examples](docs/CLIENT_EXAMPLES.md) for complete working code.**

---

## 🚨 Troubleshooting

<a name="troubleshooting"></a>

### Common Issues

**❌ Getting 401 during token exchange?**

This is usually one of three things:

1. **Missing client_secret** (confidential clients)
   ```bash
   # Check your client configuration
   python3 -c "import sqlite3; conn = sqlite3.connect('oauth.db');
   print(conn.execute('SELECT client_id, token_endpoint_auth_method, client_secret
   FROM oauth2_client WHERE client_id=\"YOUR_CLIENT_ID\"').fetchone())"
   ```
   → [Full solution in Troubleshooting Guide](docs/TROUBLESHOOTING.md#-401-unauthorized-at-token)

2. **Missing PKCE** (public clients)
   → [See PKCE implementation guide](docs/TROUBLESHOOTING.md#-401-unauthorized-at-token)

3. **redirect_uri mismatch**
   → Must match exactly in both authorize and token requests

**❌ Session/state lost during OAuth redirect?**
- [Use the stateless approach](docs/CLIENT_EXAMPLES.md#example-2-stateless-oauth2-embedding-pkce-in-state) (embed PKCE verifier in signed state)

**❌ Still having issues?**
- 📕 **[Complete Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Covers all error scenarios
- 💻 **[Working Code Examples](docs/CLIENT_EXAMPLES.md)** - Copy and adapt
- ✅ **[Integration Checklist](docs/TROUBLESHOOTING.md#integration-checklist)** - Verify your setup

---

## 📚 Demo Applications & Integrations

### Included Demo Apps

Two complete, working OAuth2 client applications:

#### Todo Demo (`todo_demo.py`)
- Complete SPA-style OAuth flow
- PKCE implementation
- Session management
- Refresh token handling

#### Camera Demo (`camera_demo.py`)
- Custom scopes demonstration
- File access permissions
- Real-world use case

```bash
# Run any demo
uv run todo_demo.py
# Open http://localhost:3000
```

### Real-World Integration: OpenSentry

**[OpenSentry](https://github.com/yourusername/OpenSentry)** - Smart security camera system with OAuth2 authentication

OpenSentry is a complete production application that integrates with this OAuth2 server for centralized authentication across multiple camera devices.

**Key Features:**
- 📹 Live video streaming with motion/object/face detection
- 🔐 OAuth2/OIDC authentication (fallback to local auth)
- 🌐 mDNS device discovery
- 🏢 Multi-device SSO support
- 🐳 Docker-ready deployment

**Quick Integration:**

```bash
# 1. Start the OAuth2 server
cd Oauth2
uv run server.py

# 2. Register OpenSentry as a client
cat > add_opensentry_client.py << 'EOF'
#!/usr/bin/env python3
import os
os.environ['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'sqlite:///oauth.db')
from server import SessionLocal, OAuth2Client

db = SessionLocal()
existing = db.query(OAuth2Client).filter_by(client_id='opensentry-device').first()

redirect_uris = 'http://localhost:5000/oauth2/callback http://127.0.0.1:5000/oauth2/callback'
scope = 'openid profile email offline_access'

if existing:
    print("Updating existing client...")
    existing.client_secret = None
    existing.client_name = 'OpenSentry Device'
    existing.redirect_uris = redirect_uris
    existing.scope = scope
    existing.grant_types = 'authorization_code refresh_token'
    existing.response_types = 'code'
    existing.token_endpoint_auth_method = 'none'
    existing.require_consent = True
    db.commit()
    print("✓ Client 'opensentry-device' updated")
else:
    print("Creating new client...")
    client = OAuth2Client(
        client_id='opensentry-device',
        client_secret=None,
        client_name='OpenSentry Device',
        redirect_uris=redirect_uris,
        scope=scope,
        grant_types='authorization_code refresh_token',
        response_types='code',
        token_endpoint_auth_method='none',
        require_consent=True
    )
    db.add(client)
    db.commit()
    print("✓ Client 'opensentry-device' created")

db.close()
EOF

uv run python add_opensentry_client.py

# 3. Start OpenSentry
cd ../OpenSentry
uv run server.py

# 4. Configure OAuth2 in OpenSentry settings
# Navigate to http://127.0.0.1:5000/settings
# Select OAuth2 Authentication
# Base URL: http://127.0.0.1:8000
# Client ID: opensentry-device
# Save and restart
```

**Benefits of OAuth2 with Multiple OpenSentry Devices:**
- ✅ **Single Sign-On** - One login for all your security cameras
- ✅ **Centralized User Management** - Add/remove users in one place
- ✅ **Audit Trail** - Track authentication across all devices
- ✅ **Enhanced Security** - MFA, token rotation, PKCE
- ✅ **Graceful Fallback** - Local auth available if OAuth2 server is down

See [OpenSentry documentation](https://github.com/yourusername/OpenSentry#-oauth2-setup-guide) for complete setup guide.

---

## 🔐 Security & Production

<a name="security-checklist"></a>

### Security Checklist

Before deploying to production:

- [ ] **Replace demo auth** - Integrate your production authentication (LDAP, SAML, etc.)
- [ ] **Generate strong `APP_SECRET`** - 32+ random bytes
- [ ] **Use environment variables** - Never hardcode secrets
- [ ] **Enforce strict `redirect_uris`** - No wildcards, exact matches only
- [ ] **Enable PKCE for public clients** - Mandatory in client policy
- [ ] **Use `client_secret_basic`** - For confidential client authentication
- [ ] **Enable rate limiting** - Protect `/token` and `/authorize` endpoints
- [ ] **Set up monitoring** - Track failed auth attempts, token usage
- [ ] **Rotate signing keys** - Periodic key rotation via Admin UI
- [ ] **Use HTTPS** - TLS termination at reverse proxy (nginx, ALB)
- [ ] **Regular backups** - Backup database (contains keys and settings)
- [ ] **Audit logging** - Log all admin actions and token operations

### Production Deployment

<a name="production-deployment"></a>

#### With Gunicorn (Recommended)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 server:app
```

#### With Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "server:app"]
```

```bash
docker build -t oauth2-server .
docker run -d -p 8000:8000 \
  -e DATABASE_URL="postgresql://..." \
  -e APP_SECRET="..." \
  oauth2-server
```

#### With Docker Compose

```yaml
version: '3.8'
services:
  oauth2:
    build: .
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://oauth:password@db:5432/oauth
      APP_SECRET: ${APP_SECRET}
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: oauth
      POSTGRES_USER: oauth
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

#### Behind Nginx (TLS Termination)

```nginx
server {
    listen 443 ssl http2;
    server_name oauth.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Production Checklist

- [ ] Use PostgreSQL or MySQL (not SQLite)
- [ ] Configure connection pooling
- [ ] Set up TLS-terminating reverse proxy
- [ ] Ensure consistent external URL (stable OIDC `issuer`)
- [ ] Enable database replication/backups
- [ ] Set up centralized logging
- [ ] Configure health checks (`/health` endpoint)
- [ ] Use secrets management (Vault, AWS Secrets Manager, etc.)
- [ ] Set up alerting for auth failures
- [ ] Document disaster recovery procedures

---

## 🛠️ Client Types Explained

| Type | Auth Method | Secret? | PKCE? | Best For |
|------|-------------|---------|-------|----------|
| **Public** | `none` | ❌ No | ✅ Required | SPAs, mobile apps, desktop apps |
| **Confidential** | `client_secret_post`<br>`client_secret_basic` | ✅ Required | ⚠️ Optional | Backend services, server-to-server |

**Public clients** can't securely store secrets (e.g., JavaScript in browser), so they **must use PKCE** for security.

**Confidential clients** run on secure servers where secrets can be protected.

---

## ❓ FAQ

<details>
<summary><strong>Is this production-ready?</strong></summary>

Yes! This server implements industry-standard OAuth 2.0 and OIDC protocols. It's used in real-world applications. Follow the [Security Checklist](#security-checklist) for production deployments.
</details>

<details>
<summary><strong>Can I use this commercially?</strong></summary>

Absolutely! MIT License means you can use it for any purpose, including commercial projects. No attribution required (but appreciated!).
</details>

<details>
<summary><strong>How does this compare to Auth0/Okta?</strong></summary>

See the [comparison table](#-vs-cloud-oauth-providers) above. Main advantages: zero cost, complete control, data privacy, no vendor lock-in.
</details>

<details>
<summary><strong>Can I integrate with my existing user database?</strong></summary>

Yes! Replace the demo login system in `server.py` with your own authentication (LDAP, database, SAML, etc.). The OAuth2/OIDC layer remains the same.
</details>

<details>
<summary><strong>Does it work offline/air-gapped?</strong></summary>

Yes! Self-hosted means no external dependencies. Perfect for secure environments without internet access.
</details>

<details>
<summary><strong>How do I reset the Admin Token?</strong></summary>

Update `server_settings.admin_token_hash` in the database, or reinitialize the database for development.
</details>

<details>
<summary><strong>Can I run multiple instances for high availability?</strong></summary>

Yes! Use a shared database (PostgreSQL with replication) and deploy multiple app instances behind a load balancer. Sessions are stored server-side in the database.
</details>

<details>
<summary><strong>What about user registration?</strong></summary>

User registration is intentionally not included (out of scope for OAuth2). Integrate your own user management system or use the `/dev/seed` helper for development.
</details>

---

## 🤝 Contributing

Contributions welcome! This project thrives on community feedback.

- 🐛 Found a bug? [Open an issue](https://github.com/Sbussiso/LOauth2/issues)
- 💡 Have an idea? [Start a discussion](https://github.com/Sbussiso/LOauth2/discussions)
- 🔧 Want to contribute code? Fork, commit, and submit a PR!

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

**Use it, modify it, sell it, deploy it anywhere. No restrictions.**

---

## 🌟 Why We Built This

We believe authentication should be:
- ✅ **Under your control** - Not locked behind a vendor
- ✅ **Privacy-respecting** - Your users' data stays with you
- ✅ **Cost-effective** - No per-user fees that scale with success
- ✅ **Transparent** - Open source means you can audit everything
- ✅ **Standards-based** - Works with any OAuth2-compatible app

Cloud OAuth providers have their place, but **you should have the choice** to self-host.

---

## 🔗 Resources & Links

### Documentation
- [📕 Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [💻 Client Code Examples](docs/CLIENT_EXAMPLES.md) - Working implementations
- [📖 API Reference](docs/API_REFERENCE.md) - Complete endpoint docs
- [⚙️ Admin UI Guide](docs/ADMIN_UI_GUIDE.md) - Configuration reference

### Related Projects
- [📹 OpenSentry](https://github.com/yourusername/OpenSentry) - Smart security camera system with OAuth2 integration
- [🎛️ OpenSentry Command](https://github.com/yourusername/OpenSentry-Command) - Device discovery and management dashboard

### Community
- [GitHub Repository](https://github.com/Sbussiso/LOauth2)
- [Issue Tracker](https://github.com/Sbussiso/LOauth2/issues)
- [Discussions](https://github.com/Sbussiso/LOauth2/discussions)

### Standards
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

---

<p align="center">
  <strong>Take back control of your authentication.</strong><br>
  <em>Self-hosted. Open source. Yours forever.</em>
</p>

<p align="center">
  <a href="#-get-started-in-60-seconds">Get Started →</a>
</p>
