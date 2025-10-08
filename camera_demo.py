from __future__ import annotations
import os
from typing import Generator
import base64
import hashlib
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, Response, render_template_string, session, redirect, request, url_for

try:
    import cv2  # type: ignore
except Exception as e:  # OpenCV optional until installed
    cv2 = None  # type: ignore
    CV2_IMPORT_ERROR = e  # type: ignore

app = Flask(__name__)
app.secret_key = os.environ.get("CLIENT_APP_SECRET", os.urandom(24))

# Camera configuration (override via env)
CAMERA_INDEX = int(os.environ.get("CAMERA_INDEX", "0"))
FRAME_WIDTH = int(os.environ.get("FRAME_WIDTH", "640"))
FRAME_HEIGHT = int(os.environ.get("FRAME_HEIGHT", "480"))

# OAuth client config
AUTH_SERVER = os.environ.get("AUTH_SERVER_URL", "http://127.0.0.1:8000")
CLIENT_ID = os.environ.get("CLIENT_ID", "demo-web")
REDIRECT_URI = os.environ.get("CAMERA_REDIRECT_URI", "http://localhost:3001/callback")
SCOPE = os.environ.get("SCOPE", "openid profile email offline_access")


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
    cfg.setdefault("authorization_endpoint", f"{AUTH_SERVER}/authorize")
    cfg.setdefault("token_endpoint", f"{AUTH_SERVER}/token")
    cfg.setdefault("userinfo_endpoint", f"{AUTH_SERVER}/userinfo")
    cfg["logout_endpoint"] = f"{AUTH_SERVER}/logout" if AUTH_SERVER else cfg.get("end_session_endpoint")
    app.config["OIDC_CFG"] = cfg
    return cfg


def _gen_pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge


def _ensure_camera():
    if cv2 is None:  # pragma: no cover
        raise RuntimeError(
            "OpenCV (cv2) is not installed. Install with: pip install opencv-python"
        )
    cam = getattr(app, "_camera", None)
    if cam is None:
        cam = cv2.VideoCapture(CAMERA_INDEX)
        # Try to set preferred size (may be ignored by some drivers)
        try:
            cam.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
            cam.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)
        except Exception:
            pass
        if not cam.isOpened():
            raise RuntimeError(f"Cannot open camera index {CAMERA_INDEX}")
        app._camera = cam
    return cam


def _frame_stream() -> Generator[bytes, None, None]:
    cam = _ensure_camera()
    while True:
        ok, frame = cam.read()
        if not ok:
            # Attempt to reinit camera once
            try:
                cam.release()
            except Exception:
                pass
            app._camera = None
            cam = _ensure_camera()
            continue
        # Encode as JPEG
        ok, buf = cv2.imencode(".jpg", frame)
        if not ok:
            continue
        chunk = buf.tobytes()
        yield (b"--frame\r\n"
               b"Content-Type: image/jpeg\r\n\r\n" + chunk + b"\r\n")


@app.route("/")
def index():
    tokens = session.get("tokens")
    user = session.get("user")
    if not tokens:
        return render_template_string(
            """
            <!doctype html>
            <meta charset='utf-8'>
            <title>Camera Demo</title>
            <style>
              body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf1;margin:0}
              .wrap{max-width:820px;margin:48px auto;padding:0 20px}
              .card{background:#151b2f;border:1px solid #26314f;border-radius:12px;padding:28px 32px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
              .btn{display:inline-block;padding:12px 16px;background:#2d6cdf;border-radius:10px;color:#fff;text-decoration:none;font-weight:600}
              .muted{color:#a7b1c2}
            </style>
            <div class='wrap'>
              <div class='card'>
                <h2>Camera Demo</h2>
                <p class='muted'>Sign in to view the camera.</p>
                <a class='btn' href='/login'>Sign in with Authorization Server</a>
              </div>
            </div>
            """
        )
    # Logged-in view
    if cv2 is None:
        return render_template_string(
            """
            <!doctype html>
            <meta charset="utf-8">
            <title>Camera Demo</title>
            <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf1;margin:0} .wrap{max-width:820px;margin:48px auto;padding:0 20px} .card{background:#151b2f;border:1px solid #26314f;border-radius:12px;padding:28px 32px;box-shadow:0 10px 30px rgba(0,0,0,.35)} .btn2{padding:6px 10px;background:#32405f;color:#dbe7ff;border-radius:8px;text-decoration:none;border:1px solid #3d4f77}</style>
            <div class="wrap">
              <div class="card">
                <h2>Camera Demo</h2>
                <p>OpenCV is not installed.</p>
                <pre>pip install opencv-python</pre>
                <p><a class='btn2' href='/logout'>Logout</a></p>
              </div>
            </div>
            """
        )
    name = (user or {}).get("preferred_username", "user")
    return render_template_string(
        """
        <!doctype html>
        <meta charset="utf-8">
        <title>Camera Demo</title>
        <style>
          body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf1;margin:0}
          .wrap{max-width:980px;margin:36px auto;padding:0 20px}
          .card{background:#151b2f;border:1px solid #26314f;border-radius:12px;padding:20px 24px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
          .row{display:flex;gap:12px;align-items:center;justify-content:space-between}
          img{width:100%;max-width:960px;border-radius:10px;border:1px solid #26314f;background:#000}
          .muted{color:#a7b1c2}
          .btn2{padding:6px 10px;background:#32405f;color:#dbe7ff;border-radius:8px;text-decoration:none;border:1px solid #3d4f77}
        </style>
        <div class="wrap">
          <div class="row">
            <h2>Live Camera</h2>
            <div>Signed in as <b>{{name}}</b> · <a class="btn2" href="/logout">Logout</a></div>
          </div>
          <div class="card">
            <p class="muted">Index: {{cam_index}} · {{w}}x{{h}}</p>
            <img src="/video_feed" alt="camera" />
          </div>
        </div>
        """,
        name=name,
        cam_index=CAMERA_INDEX,
        w=FRAME_WIDTH,
        h=FRAME_HEIGHT,
    )


@app.route("/login")
def login():
    if session.get("tokens"):
        return redirect(url_for("index"))
    code_verifier, code_challenge = _gen_pkce()
    session["code_verifier"] = code_verifier
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
    return redirect(cfg["authorization_endpoint"] + "?" + urlencode(params))


@app.route("/callback")
def callback():
    error = request.args.get("error")
    if error:
        return Response(f"Authorization error: {error}", status=400)
    state = request.args.get("state")
    if not state or state != session.get("oauth_state"):
        return Response("Invalid or missing state. Please start over at /login", status=400)
    code = request.args.get("code")
    if not code:
        return Response("Missing authorization code", status=400)
    code_verifier = session.get("code_verifier")
    if not code_verifier:
        return Response("Missing PKCE verifier in session. Start over at /login", status=400)
    cfg = _get_oidc()
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    resp = requests.post(cfg["token_endpoint"], data=data, timeout=10)
    if resp.status_code != 200:
        return Response(f"Token exchange failed: {resp.status_code} {resp.text}", status=resp.status_code)
    session["tokens"] = resp.json()
    # Fetch userinfo
    try:
        ui = requests.get(cfg["userinfo_endpoint"], headers={"Authorization": f"Bearer {session['tokens']['access_token']}"}, timeout=10)
        if ui.status_code == 200:
            session["user"] = ui.json()
    except Exception:
        pass
    session.pop("oauth_state", None)
    return redirect(url_for("index"))


@app.route("/video_feed")
def video_feed():
    if not session.get("tokens"):
        return redirect(url_for("index"))
    if cv2 is None:  # pragma: no cover
        return Response("OpenCV not installed", status=500)
    return Response(_frame_stream(), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route("/logout")
def logout():
    tokens = session.get("tokens") or {}
    idt = tokens.get("id_token")
    params = {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": url_for("index", _external=True),
        "state": secrets.token_urlsafe(12),
    }
    if idt:
        params["id_token_hint"] = idt
    cfg = _get_oidc()
    logout_ep = cfg.get("logout_endpoint") or cfg.get("end_session_endpoint") or f"{AUTH_SERVER}/logout"
    # Clear local session after building redirect
    session.clear()
    return redirect(logout_ep + "?" + urlencode(params))


@app.route("/healthz")
def healthz():
    return "ok"


@app.teardown_appcontext
def _cleanup(_):
    cam = getattr(app, "_camera", None)
    if cam is not None:
        try:
            cam.release()
        except Exception:
            pass
    app._camera = None


if __name__ == "__main__":
    # Run on 3001 by default so it can coexist with todo_demo on 3000
    app.run(host="localhost", port=int(os.environ.get("PORT", "3001")), debug=True)
