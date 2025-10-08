from __future__ import annotations
import os
import base64
import hashlib
from urllib.parse import urlencode
import secrets

import requests
from flask import Flask, session, redirect, request, url_for, jsonify, Response

# Minimal OAuth2 client app that uses the local authorization server (server.py)
# Runs on http://localhost:3000 and performs the Authorization Code + PKCE flow.

AUTH_SERVER = os.environ.get("AUTH_SERVER_URL", "http://127.0.0.1:5000")
CLIENT_ID = os.environ.get("CLIENT_ID", "demo-web")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:3000/callback")
# Request offline_access so the server returns a refresh_token on auth_code exchange
SCOPE = os.environ.get("SCOPE", "openid profile email offline_access")

app = Flask(__name__)
app.secret_key = os.environ.get("CLIENT_APP_SECRET", os.urandom(24))

# In-memory demo storage for todos keyed by user id (sub)
TODOS: dict[int, list[dict]] = {}
TODO_NEXT_ID: dict[int, int] = {}

AUTH_COMPLETE_TEMPLATE = """
<!doctype html>
<meta charset="utf-8">
<title>Authentication Complete</title>
<style>
 body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b1020; color:#e8ecf1; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
 .card { background:#151b2f; border:1px solid #26314f; border-radius:12px; padding:28px 32px; max-width:560px; box-shadow: 0 10px 30px rgba(0,0,0,.35); }
 .title { font-size:1.25rem; margin:0 0 8px; }
 .muted { color:#a7b1c2; margin:0 0 16px; }
 .btn { display:inline-block; padding:10px 14px; background:#2d6cdf; border-radius:8px; color:#fff; text-decoration:none; font-weight:600; }
 .btn:active { transform: translateY(1px); }
 .row { display:flex; gap:12px; align-items:center; }
 code { background:#0f1426; padding:2px 6px; border-radius:6px; }
 .ok { color:#42d392 }
 .dot { width:10px; height:10px; background:#42d392; border-radius:50%; display:inline-block; margin-right:6px; }
</style>
<div class="card">
  <h2 class="title">You're signed in</h2>
  <p class="muted">This window can be closed. Your app will refresh automatically.</p>
  <div class="row">
    <span class="dot"></span><span>Auth status: <b class="ok">Completed</b></span>
  </div>
  <p class="muted">If this window doesn't close automatically, click below.</p>
  <a class="btn" href="/">Return to app</a>
</div>
<script>
  (function(){
    try {
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage({ type: 'oauth:login:success' }, window.location.origin);
        setTimeout(function(){ window.close(); }, 400);
      }
    } catch(e) {}
  })();
</script>
"""


def _gen_pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge


def _get_oidc():
    """Fetch and cache OIDC discovery. Fallback to static endpoints."""
    cfg = app.config.get("OIDC_CFG")
    if cfg:
        return cfg
    cfg = {}
    try:
        r = requests.get(f"{AUTH_SERVER}/.well-known/openid-configuration", timeout=5)
        if r.status_code == 200:
            j = r.json()
            cfg["issuer"] = j.get("issuer")
            cfg["authorization_endpoint"] = j.get("authorization_endpoint", f"{AUTH_SERVER}/authorize")
            cfg["token_endpoint"] = j.get("token_endpoint", f"{AUTH_SERVER}/token")
            cfg["userinfo_endpoint"] = j.get("userinfo_endpoint", f"{AUTH_SERVER}/userinfo")
            cfg["end_session_endpoint"] = j.get("end_session_endpoint")
    except Exception:
        pass
    # Fallbacks
    cfg.setdefault("authorization_endpoint", f"{AUTH_SERVER}/authorize")
    cfg.setdefault("token_endpoint", f"{AUTH_SERVER}/token")
    cfg.setdefault("userinfo_endpoint", f"{AUTH_SERVER}/userinfo")
    # Prefer robust RP logout route; if not present, use end_session
    cfg["logout_endpoint"] = f"{AUTH_SERVER}/logout" if AUTH_SERVER else cfg.get("end_session_endpoint")
    app.config["OIDC_CFG"] = cfg
    return cfg


@app.route("/")
def home():
    tokens = session.get("tokens")
    user = session.get("user")
    if not tokens:
        # Logged out view with a popup-based login and postMessage handling
        return """
        <!doctype html>
        <meta charset='utf-8'>
        <title>Todo App</title>
        <style>
          body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf1;margin:0}
          .wrap{max-width:820px;margin:48px auto;padding:0 20px}
          .card{background:#151b2f;border:1px solid #26314f;border-radius:12px;padding:28px 32px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
          h1{margin:0 0 8px;font-size:1.6rem}
          p.muted{color:#a7b1c2}
          .btn{display:inline-block;padding:12px 16px;background:#2d6cdf;border-radius:10px;color:#fff;text-decoration:none;font-weight:600}
        </style>
        <div class='wrap'>
          <div class='card'>
            <h1>Todo App</h1>
            <p class='muted'>Sign in to manage your tasks.</p>
            <a class='btn' href='/login' onclick='return openLogin(event)'>Sign in with Authorization Server</a>
          </div>
        </div>
        <script>
          function openLogin(ev){
            ev.preventDefault();
            window.open('/login','oauthLogin','width=520,height=720');
            return false;
          }
          window.addEventListener('message', function(ev){
            if (ev.origin !== window.location.origin) return;
            if (ev.data && ev.data.type === 'oauth:login:success') {
              window.location.reload();
            }
          });
        </script>
        """

    # Logged in view: show a Todo list UI
    # Refresh userinfo if missing
    if not user and tokens:
        api = f"{AUTH_SERVER}/userinfo"
        r = requests.get(api, headers={"Authorization": f"Bearer {tokens.get('access_token')}"}, timeout=10)
        if r.status_code == 200:
            user = r.json()
            session["user"] = user
    username = (user or {}).get("preferred_username", "user")
    uid = (user or {}).get("sub")
    todo_list = TODOS.get(uid, [])
    # Render a simple form-based UI
    html = [
        "<!doctype html>",
        "<meta charset='utf-8'>",
        "<title>Todo App</title>",
        "<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf1;margin:0} .wrap{max-width:900px;margin:36px auto;padding:0 20px} .nav{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px} .brand{font-weight:700} .card{background:#151b2f;border:1px solid #26314f;border-radius:12px;padding:20px 24px;box-shadow:0 10px 30px rgba(0,0,0,.35)} .btn{padding:8px 12px;background:#2d6cdf;color:#fff;border-radius:8px;text-decoration:none;font-weight:600} .btn2{padding:6px 10px;background:#32405f;color:#dbe7ff;border-radius:8px;text-decoration:none;border:1px solid #3d4f77} form.inline{display:inline} input[type=text]{padding:10px 12px;border-radius:8px;border:1px solid #3d4f77;background:#0f1426;color:#e8ecf1;min-width:280px} ul{list-style:none;padding:0;margin:0} li.item{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #26314f} .muted{color:#a7b1c2} .title{display:flex;align-items:center;gap:10px} .done{text-decoration:line-through;color:#9ab} .row{display:flex;gap:10px;align-items:center}</style>",
        "<div class='wrap'>",
        f"<div class='nav'><div class='brand'>Todo App</div><div>Signed in as <b>{username}</b> · <a class='btn2' href='/logout'>Logout</a></div></div>",
        "<div class='card'>",
        "<h2>Your Tasks</h2>",
        "<form method='post' action='/todos/add' class='row'><input name='title' type='text' placeholder='Add a new task' required> <button class='btn' type='submit'>Add</button></form>",
        "<ul>",
    ]
    for item in todo_list:
        css = 'done' if item.get('done') else ''
        html.append(
            f"<li class='item'><div class='title {css}'>"
            f"<form class='inline' method='post' action='/todos/toggle/{item['id']}'><button class='btn2' type='submit'>{'✓' if item.get('done') else '○'}</button></form>"
            f"<span>{item['title']}</span></div>"
            f"<form class='inline' method='post' action='/todos/delete/{item['id']}'><button class='btn2' type='submit'>Delete</button></form></li>"
        )
    if not todo_list:
        html.append("<li class='item muted'>No tasks yet</li>")
    html.extend(["</ul>", "</div>", "</div>"])
    return "".join(html)


@app.route("/login")
def login():
    # Prevent accidental re-login while already authenticated
    if session.get("tokens"):
        return (
            "<h3>Already logged in</h3>"
            "<p>Please <a href='/logout'>logout</a> before starting a new login.</p>"
        )
    # Generate PKCE values and store verifier in session
    code_verifier, code_challenge = _gen_pkce()
    session["code_verifier"] = code_verifier
    # CSRF protection: include state and verify it in /callback
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
        "state": state,
    }
    cfg = _get_oidc()
    authorize_url = cfg["authorization_endpoint"] + "?" + urlencode(params)
    return redirect(authorize_url)


@app.route("/callback")
def callback():
    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", "")
        return Response(f"Authorization error: {error} {desc}", status=400)

    # Verify state to prevent CSRF/accidental navigations
    state = request.args.get("state")
    expected_state = session.get("oauth_state")
    if not state or not expected_state or state != expected_state:
        return Response("Invalid or missing state. Please start over at /login", status=400)

    code = request.args.get("code")
    if not code:
        return Response("Missing authorization code", status=400)

    code_verifier = session.get("code_verifier")
    if not code_verifier:
        return Response("Missing PKCE verifier in session. Start over at /login", status=400)

    cfg = _get_oidc()
    token_url = cfg["token_endpoint"]
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    resp = requests.post(token_url, data=data, timeout=10)
    if resp.status_code != 200:
        return Response(f"Token exchange failed: {resp.status_code} {resp.text}", status=resp.status_code)

    session["tokens"] = resp.json()
    # Fetch userinfo once and store
    try:
        cfg = _get_oidc()
        ui = requests.get(cfg["userinfo_endpoint"], headers={"Authorization": f"Bearer {session['tokens']['access_token']}"}, timeout=10)
        if ui.status_code == 200:
            session["user"] = ui.json()
    except Exception:
        pass
    # One-time use: clear oauth_state after successful exchange
    session.pop("oauth_state", None)
    # Render a small completion page that closes the popup and notifies opener
    return Response(AUTH_COMPLETE_TEMPLATE, status=200, content_type="text/html")


# /me route removed; use curl against the auth server's /userinfo for debugging


# /refresh route removed for a minimal test app


@app.route("/todos/add", methods=["POST"])
def todos_add():
    tokens = session.get("tokens")
    user = session.get("user")
    if not tokens or not user:
        return redirect(url_for("home"))
    title = (request.form.get("title") or "").strip()
    if not title:
        return redirect(url_for("home"))
    uid = user.get("sub")
    if uid not in TODOS:
        TODOS[uid] = []
        TODO_NEXT_ID[uid] = 1
    item = {"id": TODO_NEXT_ID[uid], "title": title, "done": False}
    TODO_NEXT_ID[uid] += 1
    TODOS[uid].append(item)
    return redirect(url_for("home"))


@app.route("/todos/toggle/<int:item_id>", methods=["POST"])
def todos_toggle(item_id: int):
    tokens = session.get("tokens")
    user = session.get("user")
    if not tokens or not user:
        return redirect(url_for("home"))
    uid = user.get("sub")
    items = TODOS.get(uid, [])
    for it in items:
        if it["id"] == item_id:
            it["done"] = not it.get("done")
            break
    return redirect(url_for("home"))


@app.route("/todos/delete/<int:item_id>", methods=["POST"])
def todos_delete(item_id: int):
    tokens = session.get("tokens")
    user = session.get("user")
    if not tokens or not user:
        return redirect(url_for("home"))
    uid = user.get("sub")
    items = TODOS.get(uid, [])
    TODOS[uid] = [it for it in items if it["id"] != item_id]
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    # Include id_token_hint when available; clear session after building redirect
    tokens = session.get("tokens") or {}
    idt = tokens.get("id_token")
    state = secrets.token_urlsafe(12)
    params = {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": url_for("home", _external=True),
        "state": state,
    }
    if idt:
        params["id_token_hint"] = idt
    cfg = _get_oidc()
    logout_ep = cfg.get("logout_endpoint") or cfg.get("end_session_endpoint") or f"{AUTH_SERVER}/logout"
    # Now clear local session
    session.clear()
    return redirect(logout_ep + "?" + urlencode(params))


if __name__ == "__main__":
    # Ensure the redirect_uri host/port match what the auth server has whitelisted
    # Defaults to http://localhost:3000/callback which is seeded by /dev/seed
    # Bind to localhost (not 127.0.0.1) so the session cookie is sent back on the callback host
    app.run(host="localhost", port=3000, debug=True)
