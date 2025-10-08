# Client Implementation Examples

## Example 1: Basic OAuth2 Client with PKCE (Python/Flask)

This example shows the complete implementation of an OAuth2 client with PKCE:

```python
import os
import base64
import hashlib
import secrets
import requests
from flask import Flask, session, redirect, request, url_for
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = os.urandom(24)

# OAuth2 Configuration
AUTH_SERVER = "http://127.0.0.1:8000"
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"  # Only for confidential clients
REDIRECT_URI = "http://localhost:3000/callback"
SCOPE = "openid profile email offline_access"

def _gen_pkce():
    """Generate PKCE code_verifier and code_challenge."""
    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge

@app.route("/login")
def login():
    # Generate PKCE values
    code_verifier, code_challenge = _gen_pkce()

    # Store verifier in session (or embed in signed state for stateless approach)
    session['code_verifier'] = code_verifier
    session['oauth_state'] = secrets.token_urlsafe(24)

    # Build authorization URL
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'state': session['oauth_state'],
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge,
    }

    auth_url = f"{AUTH_SERVER}/authorize?" + urlencode(params)
    return redirect(auth_url)

@app.route("/callback")
def callback():
    # Verify state
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return "Invalid state", 400

    # Get authorization code
    code = request.args.get('code')
    if not code:
        return "Missing code", 400

    # Exchange code for tokens
    code_verifier = session.get('code_verifier')
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier,
    }

    # Add client_secret for confidential clients
    if CLIENT_SECRET:
        token_data['client_secret'] = CLIENT_SECRET

    response = requests.post(f"{AUTH_SERVER}/token", data=token_data)

    if response.status_code != 200:
        return f"Token exchange failed: {response.status_code} {response.text}", 502

    tokens = response.json()
    session['tokens'] = tokens
    session.pop('oauth_state', None)
    session.pop('code_verifier', None)

    return redirect(url_for('index'))
```

## Example 2: Stateless OAuth2 (Embedding PKCE in State)

For applications where session persistence is unreliable (cross-domain redirects), embed the `code_verifier` in a cryptographically signed state parameter:

```python
import hmac
import json
import time

def _make_state(extra=None):
    """Create signed state with embedded data."""
    payload = {
        't': int(time.time()),
        'n': secrets.token_urlsafe(16)
    }
    if extra:
        payload.update(extra)

    raw = json.dumps(payload, separators=(',', ':')).encode()
    sig = hmac.new(app.secret_key, raw, hashlib.sha256).digest()

    return base64.urlsafe_b64encode(raw).decode().rstrip('=') + '.' + \
           base64.urlsafe_b64encode(sig).decode().rstrip('=')

def _verify_state(state, max_age=600):
    """Verify and extract data from signed state."""
    try:
        raw_b64, sig_b64 = state.split('.')
        raw = base64.urlsafe_b64decode(raw_b64 + '=' * (-len(raw_b64) % 4))
        sig = base64.urlsafe_b64decode(sig_b64 + '=' * (-len(sig_b64) % 4))

        expected = hmac.new(app.secret_key, raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None

        data = json.loads(raw.decode())
        if int(time.time()) - data.get('t', 0) > max_age:
            return None

        return data
    except Exception:
        return None

@app.route("/login")
def login_stateless():
    code_verifier, code_challenge = _gen_pkce()

    # Embed code_verifier in signed state
    state = _make_state(extra={'v': code_verifier})

    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'state': state,
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge,
    }

    auth_url = f"{AUTH_SERVER}/authorize?" + urlencode(params)
    return redirect(auth_url)

@app.route("/callback")
def callback_stateless():
    state = request.args.get('state')
    code = request.args.get('code')

    # Verify state and extract code_verifier
    state_data = _verify_state(state)
    if not state_data or 'v' not in state_data:
        return "Invalid state", 400

    code_verifier = state_data['v']

    # Exchange code for tokens (same as before)
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier,
    }

    if CLIENT_SECRET:
        token_data['client_secret'] = CLIENT_SECRET

    response = requests.post(f"{AUTH_SERVER}/token", data=token_data)

    if response.status_code != 200:
        return f"Token exchange failed: {response.status_code}", 502

    tokens = response.json()
    session['tokens'] = tokens
    return redirect(url_for('index'))
```

## Demo Applications

The repository includes two complete working examples:

- **`todo_demo.py`**: Complete working example of SPA-style OAuth code flow with PKCE
- **`camera_demo.py`**: Similar flow with file access scopes

Both demos are fully functional and can be used as reference implementations.

### Running the Demo Apps

```bash
# Start the OAuth2 server
export ENABLE_DEV_ENDPOINTS=true
uv run server.py

# In another terminal, run the demo
uv run todo_demo.py

# Open http://localhost:3000 in your browser
```

---

[← Back to Main README](../README.md)
