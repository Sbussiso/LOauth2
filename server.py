"""
Minimal OAuth2 Authorization Server in Python
--------------------------------------------
Features:
- OAuth 2.0 Authorization Code grant with PKCE
- Consent screen (Google-style approve/deny)
- Refresh tokens (rotating)
- Scope support (openid, profile, email as examples; you can add custom scopes)
- User login (very simple demo, replace with your auth)
- Client registration (static seed + CLI helper to add more)

Stack:
- Flask
- Authlib (authorization server)
- SQLAlchemy (SQLite for demo)

Run:
  python3 -m venv .venv && source .venv/bin/activate
  pip install flask authlib sqlalchemy
  python server.py  # starts on http://127.0.0.1:8000

Test OAuth Flow (PKCE):
  1) Create a client: GET http://127.0.0.1:8000/dev/seed (or POST /dev/create_client)
  2) Generate PKCE verifier & challenge (script printed at startup).
  3) Hit /authorize in a browser; login user: alice / password: alice
  4) Approve consent; code returns to redirect_uri; POST to /token with code+verifier

Security Notes:
- Demo uses HTTP and SQLite; for production, use HTTPS and Postgres/MySQL.
- Replace demo login, password policy, session security, CSRF protection
- Strictly validate redirect_uris; never use wildcards in prod
- Configure token lifetimes and refresh-token rotation

This file intentionally keeps templates inline (render_template_string) so you can run from one file.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import os
import base64
import secrets
import hashlib
from urllib.parse import urlencode, urlparse
import json

from flask import Flask, request, redirect, session, url_for, abort, jsonify, render_template_string
from flask import make_response
from werkzeug.security import gen_salt, generate_password_hash, check_password_hash

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy import create_engine
from sqlalchemy.orm import relationship, sessionmaker, scoped_session, declarative_base, selectinload

from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import grants
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector, current_token
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.jose import jwt, JsonWebKey

# ----------------------
# Flask & DB Setup
# ----------------------
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", os.urandom(32))
# Keep the Authorization Server session for 30 days unless explicitly logged out
app.permanent_session_lifetime = timedelta(days=30)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///oauth.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

# ----------------------
# Models
# ----------------------
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(40), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    email = Column(String(120), unique=True)

    def verify_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

class OAuth2Client(Base):
    __tablename__ = 'oauth2_client'
    id = Column(Integer, primary_key=True)
    client_id = Column(String(48), unique=True, nullable=False)
    client_secret = Column(String(120), nullable=True)  # public clients may be None
    client_name = Column(String(120))
    client_uri = Column(String(256))
    logo_uri = Column(String(256))
    grant_types = Column(String(120))  # space separated
    redirect_uris = Column(Text)       # space/newline separated
    response_types = Column(String(120))
    scope = Column(Text)               # space separated
    token_endpoint_auth_method = Column(String(120), default="none")
    require_consent = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def check_redirect_uri(self, uri: str) -> bool:
        if not self.redirect_uris:
            return False
        allowed = [u.strip() for u in self.redirect_uris.replace("\n", " ").split(" ") if u.strip()]
        return uri in allowed

    def get_default_redirect_uri(self) -> str | None:
        if not self.redirect_uris:
            return None
        allowed = [u.strip() for u in self.redirect_uris.replace("\n", " ").split(" ") if u.strip()]
        return allowed[0] if allowed else None

    def get_allowed_scope(self, scope: str) -> str:
        if not scope:
            return ''
        client_scopes = set(scope_to_list(self.scope))
        req = set(scope_to_list(scope))
        return ' '.join(sorted(req & client_scopes))

    def check_client_secret(self, secret: str | None) -> bool:
        if self.token_endpoint_auth_method == 'none':
            return True
        return bool(secret and secrets.compare_digest(self.client_secret or '', secret))

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        """
        Authlib calls this to verify the client's allowed auth method for a given endpoint.
        We only store a single setting (`token_endpoint_auth_method`) and use it for the token endpoint.
        Valid values include: 'none', 'client_secret_basic', 'client_secret_post'.
        """
        configured = (self.token_endpoint_auth_method or '').strip() or 'client_secret_basic'
        if endpoint == 'token':
            # Public clients (no client_secret) may use 'none' (and often send only client_id in body)
            if not self.client_secret:
                return method in ('none', 'client_secret_post')
            return method == configured
        # For unknown endpoints, be strict.
        return False

    def check_response_type(self, response_type: str) -> bool:
        if not self.response_types:
            return False
        allowed = [t.strip() for t in self.response_types.replace("\n", " ").split(" ") if t.strip()]
        return response_type in allowed

    def check_grant_type(self, grant_type: str) -> bool:
        if not self.grant_types:
            return False
        allowed = [t.strip() for t in self.grant_types.replace("\n", " ").split(" ") if t.strip()]
        return grant_type in allowed

    @property
    def client_id_issued_at(self):
        return int(self.created_at.timestamp())

    @property
    def client_secret_expires_at(self):
        return 0

class OAuth2AuthorizationCode(Base):
    __tablename__ = 'oauth2_code'
    id = Column(Integer, primary_key=True)
    code = Column(String(120), unique=True, nullable=False)
    client_id = Column(String(48), nullable=False)
    redirect_uri = Column(String(256), nullable=False)
    scope = Column(Text)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship('User')
    code_challenge = Column(String(128))
    code_challenge_method = Column(String(10))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_in = Column(Integer, default=600)
    consumed = Column(Boolean, default=False)

    def is_expired(self):
        return datetime.now(timezone.utc) > self.created_at + timedelta(seconds=self.expires_in)

    # Authlib v1 expects these helpers on the authorization code model
    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return (self.scope or '')

class OAuth2Token(Base):
    __tablename__ = 'oauth2_token'
    id = Column(Integer, primary_key=True)
    client_id = Column(String(48), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship('User')
    token_type = Column(String(40))
    access_token = Column(String(255), unique=True)
    refresh_token = Column(String(255), unique=True, nullable=True)
    scope = Column(Text)
    revoked = Column(Boolean, default=False)
    issued_at = Column(Integer, default=lambda: int(datetime.now(timezone.utc).timestamp()))
    expires_in = Column(Integer, default=3600)

    def is_expired(self) -> bool:
        """Authlib expects tokens to implement is_expired()."""
        now = int(datetime.now(timezone.utc).timestamp())
        return now >= (self.issued_at + (self.expires_in or 0))

    def is_revoked(self) -> bool:
        """Authlib v1 calls token.is_revoked() during resource validation."""
        return bool(self.revoked)

    def is_refresh_token_active(self):
        if self.revoked or not self.refresh_token:
            return False
        # Default 30 days, can be overridden by per-client policy
        ttl_days = 30
        db = SessionLocal()
        try:
            pol = db.query(ClientPolicy).filter_by(client_id=self.client_id).first()
            if pol and pol.refresh_token_ttl_days:
                ttl_days = int(pol.refresh_token_ttl_days)
        except Exception:
            pass
        finally:
            db.close()
        return int(datetime.now(timezone.utc).timestamp()) < self.issued_at + ttl_days * 24 * 3600

    # Authlib's ResourceProtector may call get_scope(); return a space-delimited string
    def get_scope(self):
        return (self.scope or '')

    # Authlib RefreshTokenGrant expects token.check_client(client)
    def check_client(self, client) -> bool:
        return self.client_id == getattr(client, 'client_id', None)

class OIDCKey(Base):
    __tablename__ = 'oidc_key'
    id = Column(Integer, primary_key=True)
    kid = Column(String(64), unique=True, nullable=False)
    alg = Column(String(16), default='RS256')
    use = Column(String(16), default='sig')
    public_jwk = Column(Text, nullable=False)
    private_jwk = Column(Text, nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Scope(Base):
    __tablename__ = 'scope'
    name = Column(String(120), primary_key=True)
    description = Column(String(256))
    claims = Column(Text)  # JSON array

class RememberedConsent(Base):
    __tablename__ = 'remembered_consent'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    client_id = Column(String(48), nullable=False)
    scope = Column(Text, nullable=False)  # normalized scope string
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class ClientPolicy(Base):
    __tablename__ = 'client_policy'
    id = Column(Integer, primary_key=True)
    client_id = Column(String(48), unique=True, nullable=False)
    allowed_scopes = Column(Text)            # space-delimited
    default_scopes = Column(Text)            # space-delimited
    post_logout_redirect_uris = Column(Text) # space-delimited
    require_pkce = Column(Boolean, default=True)
    consent_policy = Column(String(16), default='once')  # 'always'|'once'|'skip'
    access_token_lifetime = Column(Integer)  # seconds
    refresh_token_ttl_days = Column(Integer) # days
    token_format = Column(String(16), default='opaque')

class ServerSettings(Base):
    __tablename__ = 'server_settings'
    id = Column(Integer, primary_key=True)
    initialized = Column(Boolean, default=False)
    admin_token_hash = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

# Create tables with checkfirst to avoid race conditions with multiple workers
try:
    Base.metadata.create_all(engine, checkfirst=True)
except Exception as e:
    # If tables already exist (race condition with multiple workers), ignore
    print(f"Note: Database tables may already exist: {e}")

# ----------------------
# OAuth2 Server Setup
# ----------------------
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"]

    def save_authorization_code(self, code, request):
        db = SessionLocal()
        # Prefer Authlib v1+ payload scope; fallback to request.scope
        payload = getattr(request, 'payload', None)
        scope_val = None
        if payload is not None:
            scope_val = getattr(payload, 'scope', None)
            if scope_val is None and isinstance(payload, dict):
                scope_val = payload.get('scope', '')
        if scope_val is None:
            scope_val = getattr(request, 'scope', '') or ''
        # Prefer payload.redirect_uri when available (avoid deprecation warning)
        redirect_uri_val = None
        if payload is not None:
            redirect_uri_val = getattr(payload, 'redirect_uri', None)
            if redirect_uri_val is None and isinstance(payload, dict):
                redirect_uri_val = payload.get('redirect_uri')
        if not redirect_uri_val:
            redirect_uri_val = request.redirect_uri
        # Prefer payload.data for PKCE fields when available
        data_obj = None
        if payload is not None:
            data_obj = getattr(payload, 'data', None)
            if data_obj is None and isinstance(payload, dict):
                data_obj = payload.get('data', None)
        item = OAuth2AuthorizationCode(
            # In Authlib v1+, `code` is a string value, not a dict
            code=code,
            client_id=request.client.client_id,
            redirect_uri=redirect_uri_val,
            scope=scope_val,
            user_id=request.user.id,
            code_challenge=(data_obj.get("code_challenge") if data_obj else request.data.get("code_challenge")),
            code_challenge_method=(data_obj.get("code_challenge_method") if data_obj else request.data.get("code_challenge_method")),
        )
        db.add(item)
        db.commit()
        db.close()
        return code

    # Ensure refresh tokens are issued on authorization_code exchange when requested/allowed
    def should_issue_refresh_token(self, request=None):
        req = request or getattr(self, 'request', None)
        # Prefer payload.scope (Authlib v1), fallback to request.scope
        payload = getattr(req, 'payload', None)
        scope_str = None
        if payload is not None:
            scope_str = getattr(payload, 'scope', None)
            if scope_str is None and isinstance(payload, dict):
                scope_str = payload.get('scope', '')
        if scope_str is None:
            scope_str = getattr(req, 'scope', '') or ''
        # OIDC-style: issue refresh token when offline_access is requested
        if 'offline_access' in scope_to_list(scope_str):
            return True
        # Or when client explicitly allows refresh_token grant type
        client = getattr(req, 'client', None)
        if client and hasattr(client, 'check_grant_type') and client.check_grant_type('refresh_token'):
            return True
        return False

    def query_authorization_code(self, code, client):
        db = SessionLocal()
        item = db.query(OAuth2AuthorizationCode).filter_by(code=code, client_id=client.client_id).first()
        db.close()
        return item

    def delete_authorization_code(self, authorization_code):
        db = SessionLocal()
        authorization_code.consumed = True
        db.add(authorization_code)
        db.commit()
        db.close()

    def authenticate_user(self, authorization_code):
        # Avoid lazy-loading 'user' on a detached instance; fetch via a new session
        db = SessionLocal()
        try:
            u = db.get(User, authorization_code.user_id)
        finally:
            db.close()
        return u

    def validate_code_challenge(self, authorization_code, request):
        # Enforce PKCE if a challenge was present during /authorize
        # Prefer request.payload.data (Authlib v1) with fallback to request.data
        payload = getattr(request, 'payload', None)
        data_obj = None
        if payload is not None:
            data_obj = getattr(payload, 'data', None)
            if data_obj is None and isinstance(payload, dict):
                data_obj = payload.get('data')
        verifier = (data_obj.get("code_verifier") if data_obj else request.data.get("code_verifier"))
        if authorization_code.code_challenge:
            if not verifier:
                raise OAuth2Error(error="invalid_grant", description="Missing code_verifier")
            method = authorization_code.code_challenge_method or "plain"
            if not CodeChallenge(method).verify(authorization_code.code_challenge, verifier):
                raise OAuth2Error(error="invalid_grant", description="Invalid code_verifier")
        return True

class RefreshTokenGrant(grants.RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = True  # rotation
    # Allow public clients (no client_secret) to refresh tokens in this demo
    TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"]

    def authenticate_refresh_token(self, refresh_token):
        db = SessionLocal()
        try:
            tok = (
                db.query(OAuth2Token)
                .options(selectinload(OAuth2Token.user))
                .filter_by(refresh_token=refresh_token)
                .first()
            )
            if tok and tok.is_refresh_token_active():
                # Touch to fully load before session closes
                _ = tok.user.id if tok.user else None
                return tok
        finally:
            db.close()

    def authenticate_user(self, credential):
        return credential.user

    def revoke_old_credential(self, credential):
        db = SessionLocal()
        credential.revoked = True
        db.add(credential)
        db.commit()
        db.close()

class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        db = SessionLocal()
        try:
            tok = (
                db.query(OAuth2Token)
                .options(selectinload(OAuth2Token.user))
                .filter_by(access_token=token_string)
                .first()
            )
            # Access relationship once to ensure it's loaded before session close
            if tok and tok.user is not None:
                _ = tok.user.id  # touch attribute to force load
            return tok
        finally:
            db.close()

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return token.revoked

require_oauth = ResourceProtector()
require_oauth.register_token_validator(MyBearerTokenValidator())

auth_server = AuthorizationServer()

# ----------------------
# OIDC signing keys (RSA) with persistence
# ----------------------
def _load_active_signing_key():
    db = SessionLocal()
    try:
        item = db.query(OIDCKey).filter_by(active=True).first()
        if not item:
            kid = os.environ.get("OIDC_JWK_KID", "dev-1")
            key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
            pub = key.as_dict(is_private=False)
            priv = key.as_dict()
            # attach kid to JWK dicts for JWKS consumers
            pub["kid"] = kid
            priv["kid"] = kid
            item = OIDCKey(kid=kid, alg='RS256', use='sig', public_jwk=json.dumps(pub), private_jwk=json.dumps(priv), active=True)
            db.add(item)
            db.commit()
        priv = json.loads(item.private_jwk)
        key = JsonWebKey.import_key(priv)
        return item.kid, key
    finally:
        db.close()

KID, SIGNING_JWK = _load_active_signing_key()

def _issuer() -> str:
    # Compute issuer based on current host, e.g., http://127.0.0.1:8000
    try:
        return (request.host_url or "http://127.0.0.1:8000/").rstrip('/')
    except RuntimeError:
        # outside request context
        return "http://127.0.0.1:8000"

def _b64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip('=')

def _make_id_token(user: User, client_id: str, access_token: str | None, expires_in: int | None) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    exp = now + int(expires_in or 3600)
    payload = {
        'iss': _issuer(),
        'sub': str(user.id),
        'aud': client_id,
        'iat': now,
        'exp': exp,
    }
    # Include at_hash when access_token is available (recommended)
    if access_token:
        h = hashlib.sha256(access_token.encode()).digest()
        half = h[:len(h)//2]
        payload['at_hash'] = _b64url_no_pad(half)
    header = {'alg': 'RS256', 'kid': KID}
    return jwt.encode(header, payload, SIGNING_JWK).decode()

def query_client(client_id: str) -> OAuth2Client | None:
    db = SessionLocal()
    client = db.query(OAuth2Client).filter_by(client_id=client_id).first()
    db.close()
    return client

# ----------------------
# Admin endpoints (secured by X-Admin-Token)
# ----------------------
def _require_admin():
    # Prefer DB-stored admin token (created via setup). Fallback to env ADMIN_TOKEN.
    hdr = (request.headers.get('X-Admin-Token') or '').strip()
    db = SessionLocal()
    try:
        s = db.query(ServerSettings).first()
    finally:
        db.close()
    if s and s.initialized and s.admin_token_hash:
        if not hdr or not check_password_hash(s.admin_token_hash, hdr):
            abort(401)
        return
    admin_token = os.environ.get('ADMIN_TOKEN')
    if not admin_token or not secrets.compare_digest(hdr, admin_token):
        abort(401)

@app.route('/admin/rotate_jwk', methods=['POST'])
def admin_rotate_jwk():
    _require_admin()
    db = SessionLocal()
    try:
        db.query(OIDCKey).filter_by(active=True).update({'active': False})
        kid = 'kid-' + secrets.token_urlsafe(6)
        key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
        pub = key.as_dict(is_private=False)
        priv = key.as_dict()
        pub["kid"] = kid
        priv["kid"] = kid
        row = OIDCKey(kid=kid, alg='RS256', use='sig', public_jwk=json.dumps(pub), private_jwk=json.dumps(priv), active=True)
        db.add(row)
        db.commit()
        global KID, SIGNING_JWK
        KID, SIGNING_JWK = row.kid, JsonWebKey.import_key(priv)
        return jsonify({'rotated': True, 'kid': row.kid})
    finally:
        db.close()

@app.route('/admin/scopes', methods=['GET', 'POST'])
def admin_scopes():
    _require_admin()
    db = SessionLocal()
    try:
        if request.method == 'GET':
            items = db.query(Scope).all()
            return jsonify([{'name': s.name, 'description': s.description, 'claims': json.loads(s.claims or '[]')} for s in items])
        data = request.json or {}
        name = data.get('name')
        if not name:
            abort(400, 'name required')
        item = db.query(Scope).filter_by(name=name).first()
        claims = data.get('claims') or []
        if item:
            item.description = data.get('description', item.description)
            item.claims = json.dumps(claims)
        else:
            item = Scope(name=name, description=data.get('description'), claims=json.dumps(claims))
            db.add(item)
        db.commit()
        return jsonify({'ok': True})
    finally:
        db.close()

@app.route('/admin/scopes/<name>', methods=['DELETE'])
def admin_delete_scope(name):
    _require_admin()
    db = SessionLocal()
    try:
        db.query(Scope).filter_by(name=name).delete()
        db.commit()
        return jsonify({'ok': True})
    finally:
        db.close()

@app.route('/admin/clients/<client_id>/policy', methods=['GET', 'POST'])
def admin_client_policy(client_id):
    _require_admin()
    db = SessionLocal()
    try:
        pol = db.query(ClientPolicy).filter_by(client_id=client_id).first()
        if request.method == 'GET':
            if not pol:
                return jsonify({})
            return jsonify({
                'client_id': pol.client_id,
                'allowed_scopes': pol.allowed_scopes,
                'default_scopes': pol.default_scopes,
                'post_logout_redirect_uris': pol.post_logout_redirect_uris,
                'require_pkce': pol.require_pkce,
                'consent_policy': pol.consent_policy,
                'access_token_lifetime': pol.access_token_lifetime,
                'refresh_token_ttl_days': pol.refresh_token_ttl_days,
                'token_format': pol.token_format,
            })
        data = request.json or {}
        if not pol:
            pol = ClientPolicy(client_id=client_id)
            db.add(pol)
        for field in ['allowed_scopes','default_scopes','post_logout_redirect_uris','consent_policy','token_format']:
            if field in data and data[field] is not None:
                setattr(pol, field, data[field])
        for field in ['require_pkce']:
            if field in data and data[field] is not None:
                setattr(pol, field, bool(data[field]))
        for field in ['access_token_lifetime','refresh_token_ttl_days']:
            if field in data and data[field] is not None:
                setattr(pol, field, int(data[field]))
        db.commit()
        return jsonify({'ok': True})
    finally:
        db.close()
@app.route('/admin/users', methods=['GET','POST'])
def admin_users():
    _require_admin()
    db = SessionLocal()
    try:
        if request.method == 'GET':
            items = db.query(User).all()
            return jsonify([
                {'id': u.id, 'username': u.username, 'email': u.email}
                for u in items
            ])
        data = request.json or {}
        username = (data.get('username') or '').strip()
        password = (data.get('password') or '').strip()
        email = (data.get('email') or '').strip() or None
        if not username or not password:
            abort(400, 'username and password required')
        if db.query(User).filter_by(username=username).first():
            abort(409, 'username already exists')
        u = User(username=username, email=email, password_hash=generate_password_hash(password))
        db.add(u)
        db.commit()
        return jsonify({'id': u.id, 'username': u.username, 'email': u.email}), 201
    finally:
        db.close()

@app.route('/admin/users/<int:user_id>', methods=['GET','DELETE'])
def admin_user_detail_api(user_id):
    _require_admin()
    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            abort(404)
        if request.method == 'GET':
            return jsonify({'id': u.id, 'username': u.username, 'email': u.email})
        # DELETE: cleanup related records then remove user
        db.query(OAuth2Token).filter_by(user_id=user_id).delete()
        db.query(OAuth2AuthorizationCode).filter_by(user_id=user_id).delete()
        db.query(RememberedConsent).filter_by(user_id=user_id).delete()
        db.delete(u)
        db.commit()
        return jsonify({'ok': True})
    finally:
        db.close()

# Legacy decorators removed; `init_app(app, query_client=..., save_token=...)` is used instead.
def get_client(client_id):
    return query_client(client_id)

def get_token(token_str):
    db = SessionLocal()
    tok = db.query(OAuth2Token).filter_by(access_token=token_str).first()
    db.close()
    return tok


# ----------------------
# Server settings & first-time setup
# ----------------------
def _get_settings() -> ServerSettings:
    db = SessionLocal()
    try:
        s = db.query(ServerSettings).first()
        if not s:
            s = ServerSettings(initialized=False)
            db.add(s)
            db.commit()
            db.refresh(s)
        return s
    finally:
        db.close()

@app.before_request
def _enforce_setup_wizard():
    # Allow the setup flow and a few public endpoints while uninitialized
    s = _get_settings()
    if s.initialized:
        return None
    path = request.path or '/'
    allowed = {
        '/setup',
        '/favicon.ico',
        '/.well-known/openid-configuration',
        '/.well-known/jwks.json',
        '/health',
    }
    if path == '/' or path.startswith('/setup'):
        return None
    if path in allowed or path.startswith('/static/'):
        return None
    # Everything else redirects to setup until initialized
    return redirect(url_for('setup'))

SETUP_TEMPLATE = """
<!doctype html>
<meta charset="utf-8">
<title>First-time Setup</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf1;margin:0}
 .wrap{max-width:720px;margin:48px auto;padding:0 20px}
 .card{background:#151b2f;border:1px solid #26314f;border-radius:12px;padding:24px 28px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
 input,button{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #3d4f77;background:#0f1426;color:#e8ecf1}
 button{margin-top:12px;background:#2d6cdf;border:none;font-weight:600}
 .muted{color:#a7b1c2}
 .ok{color:#42d392}
 code{background:#0f1426;padding:2px 6px;border-radius:6px}
 .row{display:flex;gap:12px;align-items:center}
 .btn{padding:8px 12px;background:#2d6cdf;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;border:none}
 .info{padding:10px 12px;border-radius:10px;border:1px solid #3d4f77;background:#0f1426}
 .copy{user-select:all}
}</style>
<div class="wrap">
  <div class="card">
    <h2>First-time Setup</h2>
    {% if not generated %}
      <p>Set an admin token to secure the Admin UI and APIs. This token will be shown once, then only a hash is stored.</p>
      <form method="post">
        <label>Admin Token (leave blank to auto-generate a secure token)
          <input name="admin_token" placeholder="e.g. copy a strong random string">
        </label>
        <button type="submit">Initialize Server</button>
      </form>
      <p class="muted">You can rotate keys, add scopes/clients later in the Admin UI.</p>
    {% else %}
      <p class="ok">Initialized.</p>
      <p>Copy your admin token now and store it securely:</p>
      <div class="info copy">{{admin_token}}</div>
      <p class="muted">Use it for Admin UI login and X-Admin-Token header for Admin APIs.</p>
      <p><a class="btn" href="{{ url_for('admin_login') }}">Go to Admin Login</a></p>
    {% endif %}
  </div>
</div>
"""

@app.route('/setup', methods=['GET','POST'])
def setup():
    s = _get_settings()
    if s.initialized:
        return redirect(url_for('admin_login'))
    if request.method == 'GET':
        return render_template_string(SETUP_TEMPLATE, generated=False)
    # POST: initialize
    token = (request.form.get('admin_token') or '').strip()
    if not token:
        token = base64.urlsafe_b64encode(os.urandom(36)).decode().rstrip('=')
    db = SessionLocal()
    try:
        s = db.query(ServerSettings).first()
        s.admin_token_hash = generate_password_hash(token)
        s.initialized = True
        s.updated_at = datetime.now(timezone.utc)
        # Ensure core scopes exist
        def upsert_scope(name, desc):
            sc = db.query(Scope).filter_by(name=name).first()
            if sc:
                sc.description = desc
            else:
                db.add(Scope(name=name, description=desc, claims=json.dumps([])))
        for name, desc in [('openid','Sign you in'),('profile','Read your basic profile'),('email','Read your email address'),('offline_access','Get a refresh token for offline access')]:
            upsert_scope(name, desc)
        db.commit()
    finally:
        db.close()
    # Show token once
    return render_template_string(SETUP_TEMPLATE, generated=True, admin_token=token)

# ----------------------
# Admin Web UI (configurable, no hardcoding)
# ----------------------
def _admin_logged_in() -> bool:
    return bool(session.get('admin'))

def _require_admin_ui():
    if not _admin_logged_in():
        nxt = request.path if request.method == 'GET' else url_for('admin_ui')
        return redirect(url_for('admin_login', next=nxt))
    return None

ADMIN_LOGIN_TEMPLATE = """
<!doctype html>
<meta charset="utf-8">
<title>Admin Login</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf1;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
 .card{background:#151b2f;border:1px solid #26314f;border-radius:12px;padding:26px 30px;width:420px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
 input,button{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #3d4f77;background:#0f1426;color:#e8ecf1}
 button{margin-top:12px;background:#2d6cdf;border:none;font-weight:600}
 .muted{color:#a7b1c2}
</style>
<div class="card">
  <h3>Admin Login</h3>
  <form method="post">
    <input name="token" placeholder="Admin token" required>
    <button type="submit">Continue</button>
  </form>
  {% if error %}<p style="color:#ff7272">{{error}}</p>{% endif %}
  <p class="muted">Use the admin token set during setup. If ADMIN_TOKEN is set in the environment and no setup token exists, it will be accepted.</p>
</div>
"""

def _admin_layout(body: str) -> str:
    return f"""
<!doctype html>
<meta charset='utf-8'>
<title>Admin</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf1;margin:0}}
 .wrap{{max-width:1000px;margin:36px auto;padding:0 20px}}
 .nav{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}}
 .card{{background:#151b2f;border:1px solid #26314f;border-radius:12px;padding:20px 24px;box-shadow:0 10px 30px rgba(0,0,0,.35)}}
 a.btn,button.btn{{padding:8px 12px;background:#2d6cdf;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;border:none}}
 input,textarea,select{{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #3d4f77;background:#0f1426;color:#e8ecf1}}
 label{{display:block;margin:10px 0 14px}}
 .field{{margin-bottom:14px}}
 .label-row{{display:flex;align-items:center;gap:8px}}
 .help{{display:inline-block;width:16px;height:16px;line-height:16px;text-align:center;border-radius:50%;background:#2d6cdf;color:#fff;font-size:12px;cursor:pointer;position:relative}}
 .help .tip{{display:none;position:absolute;top:22px;left:0;background:#0f1426;border:1px solid #3d4f77;color:#e8ecf1;padding:10px 14px;border-radius:8px;max-width:480px;z-index:100}}
 .help:focus .tip,.help:hover .tip{{display:block}}
 table{{width:100%;border-collapse:collapse}}
 th,td{{padding:8px;border-bottom:1px solid #26314f}}
 .row{{display:flex;gap:12px;align-items:center}}
</style>
<div class='wrap'>
  <div class='nav'><div><b>OAuth2 Admin</b></div><div><a class='btn' href='/admin/ui'>Dashboard</a> <a class='btn' href='https://github.com/Sbussiso/LOauth2#admin-ui-reference' target='_blank' rel='noopener'>Docs</a> <a class='btn' href='/admin/logout'>Logout</a></div></div>
  <div class='card'>
    {body}
  </div>
</div>
"""

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'GET':
        return render_template_string(ADMIN_LOGIN_TEMPLATE)
    token = (request.form.get('token') or '').strip()
    # Prefer DB-stored token when initialized
    db = SessionLocal()
    try:
        s = db.query(ServerSettings).first()
    finally:
        db.close()
    valid = False
    if s and s.initialized and s.admin_token_hash:
        if token and check_password_hash(s.admin_token_hash, token):
            valid = True
    else:
        env_token = os.environ.get('ADMIN_TOKEN')
        if token and env_token and secrets.compare_digest(token, env_token):
            valid = True
    if valid:
        session['admin'] = True
        dest = request.args.get('next') or url_for('admin_ui')
        return redirect(dest)
    return render_template_string(ADMIN_LOGIN_TEMPLATE, error='Invalid token')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/ui')
def admin_ui():
    r = _require_admin_ui()
    if r: return r
    body = """
    <h2>Settings</h2>
    <p>Manage configuration without hardcoding. Use the panels below to configure scopes, clients, and signing keys.</p>
    <div class='row'>
      <a class='btn' href='/admin/ui/scopes'>Scopes</a>
      <a class='btn' href='/admin/ui/users'>Users</a>
      <a class='btn' href='/admin/ui/clients'>Clients</a>
      <a class='btn' href='/admin/ui/keys'>Signing Keys</a>
    </div>
    """
    return render_template_string(_admin_layout(body))


@app.route('/admin/ui/scopes', methods=['GET','POST'])
def admin_ui_scopes():
    r = _require_admin_ui()
    if r: return r
    db = SessionLocal()
    try:
        if request.method == 'POST':
            name = (request.form.get('name') or '').strip()
            desc = (request.form.get('description') or '').strip()
            claims_raw = (request.form.get('claims') or '').strip()
            claims = [c.strip() for c in claims_raw.split(',') if c.strip()]
            if name:
                s = db.query(Scope).filter_by(name=name).first()
                if s:
                    s.description = desc
                    s.claims = json.dumps(claims)
                else:
                    db.add(Scope(name=name, description=desc, claims=json.dumps(claims)))
                db.commit()
            return redirect(url_for('admin_ui_scopes'))
        items = db.query(Scope).all()
        rows = ''.join([f"<tr><td>{s.name}</td><td>{s.description or ''}</td><td>{json.loads(s.claims or '[]')}</td>" \
                         f"<td><form method='post' action='/admin/ui/scopes/delete' style='display:inline'><input type='hidden' name='name' value='{s.name}'><button class='btn' type='submit'>Delete</button></form></td></tr>" for s in items])
    finally:
        db.close()
    body = f"""
    <h3>Scopes</h3>
    <table><tr><th>Name</th><th>Description</th><th>Claims</th><th>Actions</th></tr>{rows}</table>
    <h4>Create / Update</h4>
    <form method='post'>
      <label>Name<input name='name' required></label>
      <label>Description<input name='description'></label>
      <label>Claims (comma-separated)<input name='claims'></label>
      <button class='btn' type='submit'>Save</button>
    </form>
    """
    return render_template_string(_admin_layout(body))

@app.route('/admin/ui/scopes/delete', methods=['POST'])
def admin_ui_scope_delete():
    r = _require_admin_ui()
    if r: return r
    name = (request.form.get('name') or '').strip()
    db = SessionLocal()
    try:
        if name:
            db.query(Scope).filter_by(name=name).delete()
            db.commit()
    finally:
        db.close()
    return redirect(url_for('admin_ui_scopes'))

@app.route('/admin/ui/users')
def admin_ui_users():
    r = _require_admin_ui()
    if r: return r
    db = SessionLocal()
    try:
        items = db.query(User).all()
        rows = ''.join([
            f"<tr><td>{u.id}</td><td>{u.username}</td><td>{u.email or ''}</td>"
            f"<td><a class='btn' href='/admin/ui/users/{u.id}'>Edit</a> "
            f"<form method='post' action='/admin/ui/users/delete' style='display:inline;margin-left:6px'>"
            f"<input type='hidden' name='user_id' value='{u.id}'><button class='btn' type='submit'>Delete</button></form></td></tr>"
            for u in items
        ])
    finally:
        db.close()
    body = f"""
    <h3>Users</h3>
    <table><tr><th>ID</th><th>Username</th><th>Email</th><th>Actions</th></tr>{rows}</table>
    <p><a class='btn' href='/admin/ui/users/new'>Create User</a></p>
    """
    return render_template_string(_admin_layout(body))

@app.route('/admin/ui/users/new', methods=['GET','POST'])
def admin_ui_users_new():
    r = _require_admin_ui()
    if r: return r
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password = (request.form.get('password') or '').strip()
        if not username or not password:
            return render_template_string(_admin_layout("<p style='color:#ff7272'>Username and password are required.</p><p><a class='btn' href='/admin/ui/users/new'>Back</a></p>"))
        db = SessionLocal()
        try:
            if db.query(User).filter_by(username=username).first():
                return render_template_string(_admin_layout("<p style='color:#ff7272'>Username already exists.</p><p><a class='btn' href='/admin/ui/users/new'>Back</a></p>"))
            u = User(username=username, email=email or None, password_hash=generate_password_hash(password))
            db.add(u)
            db.commit()
            uid = u.id
        finally:
            db.close()
        return redirect(url_for('admin_ui_user_detail', user_id=uid))
    body = """
      <h3>Create User</h3>
      <form method='post'>
        <label class='field'>
          <div class='label-row'>Username</div>
          <input name='username' required>
        </label>
        <label class='field'>
          <div class='label-row'>Email</div>
          <input name='email'>
        </label>
        <label class='field'>
          <div class='label-row'>Password</div>
          <input type='password' name='password' required>
        </label>
        <button class='btn' type='submit'>Create</button>
      </form>
    """
    return render_template_string(_admin_layout(body))

@app.route('/admin/ui/users/<int:user_id>', methods=['GET','POST'])
def admin_ui_user_detail(user_id):
    r = _require_admin_ui()
    if r: return r
    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            return render_template_string(_admin_layout(f"<p>User not found: {user_id}</p>"))
        if request.method == 'POST':
            action = request.form.get('action') or 'update'
            if action == 'update':
                email = (request.form.get('email') or '').strip()
                new_pw = (request.form.get('password') or '').strip()
                u.email = email or None
                if new_pw:
                    u.password_hash = generate_password_hash(new_pw)
                db.add(u)
                db.commit()
                return redirect(url_for('admin_ui_user_detail', user_id=user_id))
            if action == 'revoke_tokens':
                # Revoke all tokens for this user (best-effort)
                toks = db.query(OAuth2Token).filter_by(user_id=user_id, revoked=False).all()
                for t in toks:
                    t.revoked = True
                    db.add(t)
                db.commit()
                return redirect(url_for('admin_ui_user_detail', user_id=user_id))
        body = f"""
        <h3>User: {u.username} (ID {u.id})</h3>
        <form method='post'>
          <input type='hidden' name='action' value='update'>
          <label class='field'>
            <div class='label-row'>Email</div>
            <input name='email' value='{u.email or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>New Password (leave blank to keep)</div>
            <input type='password' name='password'>
          </label>
          <button class='btn' type='submit'>Save</button>
        </form>
        <hr>
        <form method='post'>
          <input type='hidden' name='action' value='revoke_tokens'>
          <button class='btn' type='submit'>Revoke All Tokens</button>
        </form>
        <p><a class='btn' href='/admin/ui/users'>Back to Users</a></p>
        """
        return render_template_string(_admin_layout(body))
    finally:
        db.close()

@app.route('/admin/ui/users/delete', methods=['POST'])
def admin_ui_user_delete():
    r = _require_admin_ui()
    if r: return r
    uid_raw = (request.form.get('user_id') or '').strip()
    try:
        uid = int(uid_raw)
    except Exception:
        return redirect(url_for('admin_ui_users'))
    db = SessionLocal()
    try:
        # Cleanup related records
        db.query(OAuth2Token).filter_by(user_id=uid).delete()
        db.query(OAuth2AuthorizationCode).filter_by(user_id=uid).delete()
        db.query(RememberedConsent).filter_by(user_id=uid).delete()
        db.query(User).filter_by(id=uid).delete()
        db.commit()
    finally:
        db.close()
    return redirect(url_for('admin_ui_users'))

@app.route('/admin/ui/clients')
def admin_ui_clients():
    r = _require_admin_ui()
    if r: return r
    db = SessionLocal()
    try:
        items = db.query(OAuth2Client).all()
        rows = ''.join([f"<tr><td>{c.client_id}</td><td>{c.client_name or ''}</td><td><a class='btn' href='/admin/ui/clients/{c.client_id}'>Edit</a> <form method='post' action='/admin/ui/clients/delete' style='display:inline;margin-left:6px'><input type='hidden' name='client_id' value='{c.client_id}'><button class='btn' type='submit'>Delete</button></form></td></tr>" for c in items])
    finally:
        db.close()
    body = f"""
    <h3>Clients</h3>
    <table><tr><th>Client ID</th><th>Name</th><th>Actions</th></tr>{rows}</table>
    <p>
      <a class='btn' href='/admin/ui/clients/wizard'>Beginner Wizard</a>
      <a class='btn' href='/admin/ui/clients/new'>Advanced Setup</a>
    </p>
    """
    return render_template_string(_admin_layout(body))
 
@app.route('/admin/ui/clients/delete', methods=['POST'])
def admin_ui_client_delete():
    r = _require_admin_ui()
    if r: return r
    client_id = (request.form.get('client_id') or '').strip()
    db = SessionLocal()
    try:
        if client_id:
            db.query(RememberedConsent).filter_by(client_id=client_id).delete()
            db.query(OAuth2AuthorizationCode).filter_by(client_id=client_id).delete()
            db.query(OAuth2Token).filter_by(client_id=client_id).delete()
            db.query(ClientPolicy).filter_by(client_id=client_id).delete()
            db.query(OAuth2Client).filter_by(client_id=client_id).delete()
            db.commit()
    finally:
        db.close()
    return redirect(url_for('admin_ui_clients'))

@app.route('/admin/ui/clients/wizard', methods=['GET','POST'])
def admin_ui_clients_wizard():
    r = _require_admin_ui()
    if r: return r
    if request.method == 'POST':
        template = (request.form.get('template') or '').strip()
        desired_id = (request.form.get('client_id') or '').strip()
        # Template presets
        public = True
        redirect_list = []
        name_hint = None
        if template == 'spa3000':
            public = True
            name_hint = 'SPA on 3000'
            redirect_list = ['http://127.0.0.1:3000/callback', 'http://localhost:3000/callback']
        elif template == 'python5000':
            public = False
            name_hint = 'Python web on 5000'
            redirect_list = ['http://127.0.0.1:5000/oauth2/callback', 'http://localhost:5000/oauth2/callback']
        elif template == 'cli5000':
            public = True
            name_hint = 'CLI/Notebook on 5000'
            redirect_list = ['http://127.0.0.1:5000/oauth2/callback', 'http://localhost:5000/oauth2/callback']
        else:
            return render_template_string(_admin_layout("<p style='color:#ff7272'>Unknown template.</p><p><a class='btn' href='/admin/ui/clients/wizard'>Back</a></p>"))

        grant_types = 'authorization_code refresh_token'
        response_types = 'code'
        scope = 'openid profile email offline_access'
        auth_method = 'none' if public else 'client_secret_post'
        secret = None if public else base64.urlsafe_b64encode(os.urandom(32)).decode()

        # Generate a unique client_id when not provided
        base_id = desired_id or (
            'spa-web' if template == 'spa3000' else (
            'python-web' if template == 'python5000' else 'cli-app'))
        db = SessionLocal()
        try:
            cid = base_id
            # Ensure uniqueness
            i = 1
            while db.query(OAuth2Client).filter_by(client_id=cid).first() is not None:
                i += 1
                cid = f"{base_id}-{i}"

            c = OAuth2Client(
                client_id=cid,
                client_secret=secret,
                client_name=name_hint or cid,
                redirect_uris=' '.join(redirect_list),
                grant_types=grant_types,
                response_types=response_types,
                scope=scope,
                token_endpoint_auth_method=auth_method,
                require_consent=True,
            )
            db.add(c)
            # Create a default policy suitable for the template
            pol = ClientPolicy(
                client_id=cid,
                allowed_scopes='openid profile email offline_access',
                default_scopes='openid profile email',
                require_pkce=True,
                consent_policy='once',
            )
            db.add(pol)
            db.commit()
        finally:
            db.close()
        return redirect(url_for('admin_ui_client_detail', client_id=cid))

    # GET: show simple template choices with optional client_id
    body = """
    <h3>Beginner Client Wizard</h3>
    <p>Select your app type. We'll prefill a secure configuration with correct redirect URIs and PKCE.</p>
    <div class='card'>
      <form method='post' style='margin-bottom:12px'>
        <input type='hidden' name='template' value='spa3000'>
        <label class='field'>Optional Client ID<input name='client_id' placeholder='e.g., my-spa'></label>
        <button class='btn' type='submit'>Create SPA (localhost:3000)</button>
      </form>
      <form method='post' style='margin-bottom:12px'>
        <input type='hidden' name='template' value='python5000'>
        <label class='field'>Optional Client ID<input name='client_id' placeholder='e.g., my-python-web'></label>
        <button class='btn' type='submit'>Create Python Web (localhost:5000)</button>
      </form>
      <form method='post'>
        <input type='hidden' name='template' value='cli5000'>
        <label class='field'>Optional Client ID<input name='client_id' placeholder='e.g., my-cli-app'></label>
        <button class='btn' type='submit'>Create CLI/Notebook (localhost:5000)</button>
      </form>
    </div>
    <p class='muted'>Looking for full control? Use <a href='/admin/ui/clients/new'>Advanced Setup</a>.</p>
    """
    return render_template_string(_admin_layout(body))

@app.route('/admin/ui/clients/new', methods=['GET','POST'])
def admin_ui_clients_new():
    r = _require_admin_ui()
    if r: return r
    if request.method == 'POST':
        client_id = (request.form.get('client_id') or '').strip()
        client_name = (request.form.get('client_name') or '').strip()
        redirect_uris = (request.form.get('redirect_uris') or '').strip()
        public = bool(request.form.get('public'))
        grant_types = (request.form.get('grant_types') or 'authorization_code refresh_token').strip()
        response_types = (request.form.get('response_types') or 'code').strip()
        scope = (request.form.get('scope') or 'openid profile email offline_access').strip()
        auth_method = 'none' if public else 'client_secret_post'
        secret = None if public else base64.urlsafe_b64encode(os.urandom(32)).decode()
        db = SessionLocal()
        try:
            if client_id and not db.query(OAuth2Client).filter_by(client_id=client_id).first():
                c = OAuth2Client(
                    client_id=client_id,
                    client_secret=secret,
                    client_name=client_name or client_id,
                    redirect_uris=redirect_uris,
                    grant_types=grant_types,
                    response_types=response_types,
                    scope=scope,
                    token_endpoint_auth_method=auth_method,
                    require_consent=True,
                )
                db.add(c)
                db.commit()
            else:
                return render_template_string(_admin_layout("<p style='color:#ff7272'>Client ID missing or already exists.</p><p><a class='btn' href='/admin/ui/clients/new'>Back</a></p>"))
        finally:
            db.close()
        return redirect(url_for('admin_ui_client_detail', client_id=client_id))
    body = """
      <h3>Create Client</h3>
      <form method='post'>
        <label class='field'>
          <div class='label-row'>Client ID <a class='help' href='https://github.com/Sbussiso/LOauth2#client-id' target='_blank' rel='noopener' title='Open docs'>i</a></div>
          <input name='client_id' required>
        </label>
        <label class='field'>
          <div class='label-row'>Client Name <a class='help' href='https://github.com/Sbussiso/LOauth2#client-name' target='_blank' rel='noopener' title='Open docs'>i</a></div>
          <input name='client_name'>
        </label>
        <label class='field'>
          <div class='label-row'>Redirect URIs <a class='help' href='https://github.com/Sbussiso/LOauth2#redirect-uris' target='_blank' rel='noopener' title='Open docs'>i</a></div>
          <textarea name='redirect_uris' rows='3'></textarea>
        </label>
        <label class='field'>
          <div class='label-row'>Scope <a class='help' href='https://github.com/Sbussiso/LOauth2#client-scope' target='_blank' rel='noopener' title='Open docs'>i</a></div>
          <input name='scope' value='openid profile email offline_access'>
        </label>
        <label class='field'>
          <div class='label-row'>Grant Types <a class='help' href='https://github.com/Sbussiso/LOauth2#grant-types' target='_blank' rel='noopener' title='Open docs'>i</a></div>
          <input name='grant_types' value='authorization_code refresh_token'>
        </label>
        <label class='field'>
          <div class='label-row'>Response Types <a class='help' href='https://github.com/Sbussiso/LOauth2#response-types' target='_blank' rel='noopener' title='Open docs'>i</a></div>
          <input name='response_types' value='code'>
        </label>
        <label class='field'>
          <div class='label-row'>Client Type <a class='help' href='https://github.com/Sbussiso/LOauth2#client-type' target='_blank' rel='noopener' title='Open docs'>i</a></div>
          <input type='checkbox' name='public' checked> Public client (no secret)
        </label>
        <button class='btn' type='submit'>Create</button>
      </form>
    """
    return render_template_string(_admin_layout(body))

@app.route('/admin/ui/clients/<client_id>', methods=['GET','POST'])
def admin_ui_client_detail(client_id):
    r = _require_admin_ui()
    if r: return r
    db = SessionLocal()
    try:
        c = db.query(OAuth2Client).filter_by(client_id=client_id).first()
        pol = db.query(ClientPolicy).filter_by(client_id=client_id).first()
        if request.method == 'POST':
            if request.form.get('action') == 'update_client' and c:
                c.client_name = request.form.get('client_name') or c.client_name
                c.redirect_uris = (request.form.get('redirect_uris') or '').strip()
                c.scope = (request.form.get('scope') or '').strip()
                c.grant_types = (request.form.get('grant_types') or '').strip()
                c.response_types = (request.form.get('response_types') or '').strip()
                c.token_endpoint_auth_method = (request.form.get('token_endpoint_auth_method') or c.token_endpoint_auth_method)
                c.require_consent = bool(request.form.get('require_consent'))
                db.add(c)
            if request.form.get('action') == 'update_policy':
                if not pol:
                    pol = ClientPolicy(client_id=client_id)
                    db.add(pol)
                pol.allowed_scopes = (request.form.get('allowed_scopes') or '').strip()
                pol.default_scopes = (request.form.get('default_scopes') or '').strip()
                pol.post_logout_redirect_uris = (request.form.get('post_logout_redirect_uris') or '').strip()
                pol.require_pkce = bool(request.form.get('require_pkce'))
                pol.consent_policy = (request.form.get('consent_policy') or 'once')
                atl = request.form.get('access_token_lifetime')
                rttl = request.form.get('refresh_token_ttl_days')
                pol.access_token_lifetime = int(atl) if atl else None
                pol.refresh_token_ttl_days = int(rttl) if rttl else None
                pol.token_format = (request.form.get('token_format') or 'opaque')
            db.commit()
            return redirect(url_for('admin_ui_client_detail', client_id=client_id))
        # Render
        if not c:
            return render_template_string(_admin_layout(f"<p>Client not found: {client_id}</p>"))
        pol = pol or ClientPolicy(client_id=client_id)
        body = f"""
        <h3>Client: {c.client_id}</h3>
        <form method='post'>
          <input type='hidden' name='action' value='update_client'>
          <label class='field'>
            <div class='label-row'>Client Name <a class='help' href='https://github.com/Sbussiso/LOauth2#client-name' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='client_name' value='{c.client_name or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Redirect URIs <a class='help' href='https://github.com/Sbussiso/LOauth2#redirect-uris' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <textarea name='redirect_uris' rows='3'>{c.redirect_uris or ''}</textarea>
          </label>
          <label class='field'>
            <div class='label-row'>Scope <a class='help' href='https://github.com/Sbussiso/LOauth2#client-scope' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='scope' value='{c.scope or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Grant Types <a class='help' href='https://github.com/Sbussiso/LOauth2#grant-types' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='grant_types' value='{c.grant_types or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Response Types <a class='help' href='https://github.com/Sbussiso/LOauth2#response-types' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='response_types' value='{c.response_types or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Token Endpoint Auth Method <a class='help' href='https://github.com/Sbussiso/LOauth2#token-endpoint-auth-method' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <select name='token_endpoint_auth_method'>
            <option value='none' {'selected' if (c.token_endpoint_auth_method or 'none')=='none' else ''}>none (public)</option>
            <option value='client_secret_post' {'selected' if (c.token_endpoint_auth_method or '')=='client_secret_post' else ''}>client_secret_post</option>
            <option value='client_secret_basic' {'selected' if (c.token_endpoint_auth_method or '')=='client_secret_basic' else ''}>client_secret_basic</option>
          </select>
          </label>
          <label class='field'>
            <div class='label-row'>Require Consent <a class='help' href='https://github.com/Sbussiso/LOauth2#require-consent' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input type='checkbox' name='require_consent' {'checked' if c.require_consent else ''}> Require consent
          </label>
          <button class='btn' type='submit'>Save Client</button>
        </form>
        <hr>
        <form method='post'>
          <input type='hidden' name='action' value='update_policy'>
          <h4>Policy</h4>
          <label class='field'>
            <div class='label-row'>Allowed Scopes <a class='help' href='https://github.com/Sbussiso/LOauth2#allowed-scopes' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='allowed_scopes' value='{pol.allowed_scopes or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Default Scopes <a class='help' href='https://github.com/Sbussiso/LOauth2#default-scopes' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='default_scopes' value='{pol.default_scopes or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Post-Logout Redirect URIs <a class='help' href='https://github.com/Sbussiso/LOauth2#post-logout-redirect-uris' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='post_logout_redirect_uris' value='{pol.post_logout_redirect_uris or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Require PKCE <a class='help' href='https://github.com/Sbussiso/LOauth2#require-pkce' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input type='checkbox' name='require_pkce' {'checked' if (pol.require_pkce if pol.require_pkce is not None else True) else ''}> Require PKCE
          </label>
          <label class='field'>
            <div class='label-row'>Consent Policy <a class='help' href='https://github.com/Sbussiso/LOauth2#consent-policy' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <select name='consent_policy'>
            <option value='always' {'selected' if (pol.consent_policy or 'once')=='always' else ''}>always</option>
            <option value='once' {'selected' if (pol.consent_policy or 'once')=='once' else ''}>once</option>
            <option value='skip' {'selected' if (pol.consent_policy or 'once')=='skip' else ''}>skip</option>
          </select>
          </label>
          <label class='field'>
            <div class='label-row'>Access Token Lifetime (seconds) <a class='help' href='https://github.com/Sbussiso/LOauth2#access-token-lifetime-seconds' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='access_token_lifetime' value='{pol.access_token_lifetime or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Refresh Token TTL (days) <a class='help' href='https://github.com/Sbussiso/LOauth2#refresh-token-ttl-days' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <input name='refresh_token_ttl_days' value='{pol.refresh_token_ttl_days or ''}'>
          </label>
          <label class='field'>
            <div class='label-row'>Token Format <a class='help' href='https://github.com/Sbussiso/LOauth2#token-format' target='_blank' rel='noopener' title='Open docs'>i</a></div>
            <select name='token_format'>
            <option value='opaque' {'selected' if (pol.token_format or 'opaque')=='opaque' else ''}>opaque (default)</option>
            <option value='jwt' {'selected' if (pol.token_format or 'opaque')=='jwt' else ''}>jwt (optional)</option>
          </select>
          </label>
          <button class='btn' type='submit'>Save Policy</button>
        </form>
        """
        return render_template_string(_admin_layout(body))
    finally:
        db.close()

@app.route('/admin/ui/keys', methods=['GET','POST'])
def admin_ui_keys():
    r = _require_admin_ui()
    if r: return r
    rotated = False
    if request.method == 'POST':
        # Rotate signing key
        db = SessionLocal()
        try:
            db.query(OIDCKey).filter_by(active=True).update({'active': False})
            kid = 'kid-' + secrets.token_urlsafe(6)
            key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
            pub = key.as_dict(is_private=False)
            priv = key.as_dict()
            pub['kid'] = kid
            priv['kid'] = kid
            row = OIDCKey(kid=kid, alg='RS256', use='sig', public_jwk=json.dumps(pub), private_jwk=json.dumps(priv), active=True)
            db.add(row)
            db.commit()
            global KID, SIGNING_JWK
            KID, SIGNING_JWK = row.kid, JsonWebKey.import_key(priv)
            rotated = True
        finally:
            db.close()
    # list keys
    db = SessionLocal()
    try:
        rows = db.query(OIDCKey).all()
        items = ''.join([f"<tr><td>{r.kid}</td><td>{'yes' if r.active else 'no'}</td><td>{r.created_at}</td></tr>" for r in rows])
    finally:
        db.close()
    body = f"""
      <h3>Signing Keys</h3>
      {'<p style=\"color:#42d392\">Rotated key successfully.</p>' if rotated else ''}
      <table><tr><th>kid</th><th>active</th><th>created</th></tr>{items}</table>
      <form method='post'><button class='btn' type='submit'>Rotate Key</button></form>
    """
    return render_template_string(_admin_layout(body))

def save_token(token, request):
    db = SessionLocal()
    try:
        # Determine grant_type from payload first (Authlib v1), fallback to request.grant_type
        payload = getattr(request, 'payload', None)
        grant_type = None
        if payload is not None:
            grant_type = getattr(payload, 'grant_type', None)
            if grant_type is None and isinstance(payload, dict):
                grant_type = payload.get('grant_type')
        if not grant_type:
            grant_type = getattr(request, 'grant_type', None)

        # If this is authorization_code, make sure a refresh_token is present when client allows it
        if grant_type == 'authorization_code':
            client = getattr(request, 'client', None)
            user = getattr(request, 'user', None)
            # Always include a refresh_token on auth code exchange in this demo
            if not token.get('refresh_token'):
                token['refresh_token'] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
            # Remove old tokens for this client+user to keep demo simple
            if client and user:
                db.query(OAuth2Token).filter_by(client_id=client.client_id, user_id=user.id).delete()
            # Per-client access token lifetime
            if client:
                pol = db.query(ClientPolicy).filter_by(client_id=client.client_id).first()
                if pol and pol.access_token_lifetime:
                    token['expires_in'] = int(pol.access_token_lifetime)
            # If openid scope requested, issue an ID Token (OIDC)
            try:
                scopes = scope_to_list(token.get('scope') or '')
                if user and client and 'openid' in scopes:
                    token['id_token'] = _make_id_token(user, client.client_id, token.get('access_token'), token.get('expires_in'))
            except Exception:
                # Non-fatal: continue without id_token
                pass

        item = OAuth2Token(
            client_id=request.client.client_id,
            user_id=request.user.id if request.user else None,
            **{k: token.get(k) for k in ['token_type','access_token','refresh_token','scope','expires_in']}
        )
        db.add(item)
        db.commit()
    finally:
        db.close()

# Initialize with Flask app
auth_server.init_app(app, query_client=query_client, save_token=save_token)
auth_server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])
auth_server.register_grant(RefreshTokenGrant)
auth_server.register_grant(grants.ClientCredentialsGrant)

# ----------------------
# Helper: session login
# ----------------------
LOGIN_TEMPLATE = """
<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b1020; color:#e8ecf1; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  .card { background:#151b2f; border:1px solid #26314f; border-radius:14px; padding:28px 32px; width: 420px; box-shadow: 0 10px 30px rgba(0,0,0,.35); }
  h2 { margin:0 0 12px; }
  label { display:block; margin:10px 0; }
  input { width:100%; padding:10px 12px; border-radius:10px; border:1px solid #3d4f77; background:#0f1426; color:#e8ecf1; }
  button { margin-top:12px; padding:12px 16px; background:#2d6cdf; color:#fff; border:none; border-radius:10px; font-weight:600; width:100%; }
  .muted { color:#a7b1c2; font-size:.95rem; }
  .brand { font-weight:700; margin-bottom:8px; }
</style>
<div class="card">
  <div class="brand">OAuth2 Server</div>
  <h2>Sign in</h2>
  <form method="post">
    <label>Username
      <input name="username" placeholder="alice" required>
    </label>
    <label>Password
      <input name="password" type="password" placeholder="alice" required>
    </label>
    <button type="submit">Continue</button>
  </form>
  <p class="muted">Demo users: <b>alice/alice</b>, <b>bob/bob</b></p>
</div>
"""

CONSENT_TEMPLATE = """
<!doctype html>
<meta charset="utf-8">
<title>Authorize {{client.client_name or client.client_id}}</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b1020; color:#e8ecf1; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .card { background:#151b2f; border:1px solid #26314f; border-radius:14px; padding:26px 30px; width: 680px; box-shadow: 0 10px 30px rgba(0,0,0,.35); }
  h2 { margin:0 0 12px; display:flex; align-items:center; gap:12px; }
  .muted { color:#a7b1c2; }
  ul { list-style:none; padding:0; }
  li { padding:8px 0; border-bottom:1px solid #26314f; }
  .row { display:flex; gap:12px; }
  .btn { padding:10px 14px; background:#2d6cdf; color:#fff; border:none; border-radius:10px; font-weight:600; }
  .btn.secondary { background:#32405f; color:#dbe7ff; border:1px solid #3d4f77; }
</style>
<div class="card">
  <h2>
    {% if client.logo_uri %}<img src="{{client.logo_uri}}" alt="logo" height="36">{% endif %}
    Authorize {{client.client_name or client.client_id}}
  </h2>
  <p class="muted">This app is requesting access to:</p>
  <ul>
    {% for s in scopes %}
      <li><b>{{s}}</b> — {{scope_desc.get(s, 'Requested permission')}}</li>
    {% endfor %}
  </ul>
  <div class="row">
    <form method="post">
      <input type="hidden" name="confirm" value="yes">
      <button class="btn" type="submit">Allow</button>
    </form>
    <form method="post">
      <input type="hidden" name="confirm" value="no">
      <button class="btn secondary" type="submit">Deny</button>
    </form>
  </div>
</div>
"""

SCOPE_DESCRIPTIONS = {
    'openid': 'Sign you in',
    'profile': 'Read your basic profile',
    'email': 'Read your email address',
    'offline_access': 'Get a refresh token for offline access',
}

# ----------------------
# Routes: login & home
# ----------------------
SIGNOUT_TEMPLATE = """
<!doctype html>
<meta charset="utf-8">
<title>Signed out</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b1020; color:#e8ecf1; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  .card { background:#151b2f; border:1px solid #26314f; border-radius:14px; padding:28px 32px; width: 520px; box-shadow: 0 10px 30px rgba(0,0,0,.35); text-align:center; }
  h2 { margin:0 0 12px; }
  .muted { color:#a7b1c2; margin:0 0 18px; }
  .btn { display:inline-block; padding:10px 14px; background:#2d6cdf; border-radius:10px; color:#fff; text-decoration:none; font-weight:600; }
</style>
<div class="card">
  <h2>You're signed out</h2>
  <p class="muted">You can close this tab now.</p>
  <a class="btn" href="/">Return to server home</a>
</div>
"""
HOME_TEMPLATE = """
<!doctype html>
<meta charset="utf-8">
<title>OAuth2 Server</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b1020; color:#e8ecf1; margin:0; }
  .wrap { max-width: 900px; margin:36px auto; padding:0 20px; }
  .card { background:#151b2f; border:1px solid #26314f; border-radius:14px; padding:22px 26px; box-shadow: 0 10px 30px rgba(0,0,0,.35); }
  .muted { color:#a7b1c2; }
  .row { display:flex; gap:12px; align-items:center; }
  .btn { padding:8px 12px; background:#2d6cdf; color:#fff; border:none; border-radius:10px; font-weight:600; text-decoration:none; }
</style>
<div class="wrap">
  <div class="card">
    <h2>OAuth2 Authorization Server</h2>
    <p class="muted">This is a demo server implementing Authorization Code + PKCE, consent, scopes, refresh tokens.</p>
    <p>Logged in: <b>{{ user.username if user else 'none' }}</b></p>
    <div class="row">
      <a class="btn" href="/dev/seed">Seed demo users/client</a>
      <a class="btn" href="/login">Log in</a>
    </div>
  </div>
</div>
"""

@app.route('/')
def index():
    u = session.get('user')
    return render_template_string(HOME_TEMPLATE, user=u)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_TEMPLATE)
    username = request.form.get('username')
    password = request.form.get('password')
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    db.close()
    if not user or not user.verify_password(password):
        return render_template_string(LOGIN_TEMPLATE + "<p style='color:red'>Invalid credentials</p>")
    # Make the AS session persistent across browser restarts (SSO-style)
    session.permanent = True
    session['user'] = {'id': user.id, 'username': user.username}
    # Continue to next
    next_url = request.args.get('next') or url_for('index')
    return redirect(next_url)

@app.route('/logout')
def logout():
    # Optional RP-initiated logout parameters
    client_id = request.args.get('client_id')
    id_token_hint = request.args.get('id_token_hint')
    post_logout_redirect_uri = request.args.get('post_logout_redirect_uri') or request.args.get('redirect_uri')
    state = request.args.get('state')
    user_info = session.get('user')
    # Infer client_id from id_token_hint if missing
    if not client_id and id_token_hint:
        db = SessionLocal()
        try:
            keys = db.query(OIDCKey).all()
        finally:
            db.close()
        for k in keys:
            try:
                pub = JsonWebKey.import_key(json.loads(k.public_jwk))
                claims = jwt.decode(id_token_hint, pub)
                claims.validate()
                aud = claims.get('aud')
                client_id = aud if isinstance(aud, str) else (aud[0] if isinstance(aud, list) and aud else None)
                if client_id:
                    break
            except Exception:
                continue
    # Best-effort: revoke all tokens for this user+client (demo behavior)
    if client_id and user_info:
        db = SessionLocal()
        try:
            toks = db.query(OAuth2Token).filter_by(client_id=client_id, user_id=user_info['id'], revoked=False).all()
            for t in toks:
                t.revoked = True
                db.add(t)
            db.commit()
        finally:
            db.close()
    session.clear()
    # Redirect back to client if instructed and allowed
    if post_logout_redirect_uri and client_id:
        db = SessionLocal()
        try:
            pol = db.query(ClientPolicy).filter_by(client_id=client_id).first()
            allowed = []
            if pol and pol.post_logout_redirect_uris:
                allowed = [u.strip() for u in pol.post_logout_redirect_uris.split() if u.strip()]
            if not allowed:
                c = query_client(client_id)
                if c and c.redirect_uris:
                    allowed = [u.strip() for u in c.redirect_uris.replace('\n',' ').split(' ') if u.strip()]
            if post_logout_redirect_uri in allowed:
                if state:
                    sep = '&' if '?' in post_logout_redirect_uri else '?'
                    return redirect(f"{post_logout_redirect_uri}{sep}state={state}")
                return redirect(post_logout_redirect_uri)
        finally:
            db.close()
    return render_template_string(SIGNOUT_TEMPLATE)

@app.route('/end_session')
def end_session():
    # OIDC-style logout endpoint
    post_logout_redirect_uri = request.args.get('post_logout_redirect_uri')
    state = request.args.get('state')
    session.clear()
    if post_logout_redirect_uri:
        if state:
            sep = '&' if '?' in post_logout_redirect_uri else '?'
            return redirect(f"{post_logout_redirect_uri}{sep}state={state}")
        return redirect(post_logout_redirect_uri)
    return render_template_string(SIGNOUT_TEMPLATE)

# ----------------------
# OAuth2: /authorize (with consent)
# ----------------------
@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    db = SessionLocal()
    try:
        # Support prompt=login to force re-authentication, even if AS session exists
        if request.method == 'GET':
            prompt = request.args.get('prompt', '')
            if 'login' in prompt.split():
                return redirect(url_for('login', next=request.url))
        user_info = session.get('user')
        if not user_info:
            # Preserve original query
            return redirect(url_for('login', next=request.url))

        user = db.get(User, user_info['id'])
        try:
            grant = auth_server.get_consent_grant(end_user=user)
        except OAuth2Error as e:
            db.close()
            return make_response((e.error, 400))

        client = grant.client
        # Require strict redirect URI match
        if not client.check_redirect_uri(grant.redirect_uri):
            db.close()
            abort(400, 'invalid redirect_uri')

        if request.method == 'GET':
            # Per-client policy
            pol = db.query(ClientPolicy).filter_by(client_id=client.client_id).first()
            # Enforce PKCE (S256) if required
            if pol and pol.require_pkce:
                ch = request.args.get('code_challenge')
                chm = (request.args.get('code_challenge_method') or '').upper()
                if not ch or chm != 'S256':
                    abort(400, 'PKCE (S256) is required for this client')
            # Prefer Authlib v1+ location: grant.request.payload.scope; fallback to grant.request.scope
            req_obj = getattr(grant, 'request', None)
            payload = getattr(req_obj, 'payload', None)
            scope_str = None
            if payload is not None:
                scope_str = getattr(payload, 'scope', None)
                if scope_str is None and isinstance(payload, dict):
                    scope_str = payload.get('scope', '')
            if scope_str is None:
                scope_str = getattr(req_obj, 'scope', '') or ''
            scopes = scope_to_list(scope_str)
            # Enforce allowed_scopes if configured
            if pol and pol.allowed_scopes:
                allowed = set(scope_to_list(pol.allowed_scopes))
                reqset = set(scopes)
                if not reqset.issubset(allowed):
                    abort(400, 'invalid_scope')
            # Consent policy: skip/once/always
            def _norm(s: str) -> str:
                return ' '.join(sorted(scope_to_list(s or '')))
            policy = (pol.consent_policy if pol and pol.consent_policy else 'once')
            if policy == 'skip':
                return auth_server.create_authorization_response(grant_user=user)
            if policy == 'once':
                rc = db.query(RememberedConsent).filter_by(user_id=user.id, client_id=client.client_id, scope=_norm(scope_str)).first()
                if rc:
                    return auth_server.create_authorization_response(grant_user=user)
            # Build scope descriptions from DB with fallback
            desc_map = {}
            db_scopes = {s.name: s for s in db.query(Scope).filter(Scope.name.in_(scopes)).all()}
            for s in scopes:
                if s in db_scopes and db_scopes[s].description:
                    desc_map[s] = db_scopes[s].description
                else:
                    desc_map[s] = SCOPE_DESCRIPTIONS.get(s, 'Requested permission')
            return render_template_string(CONSENT_TEMPLATE, client=client, scopes=scopes, scope_desc=desc_map)

        # POST: handle consent
        if request.form.get('confirm') == 'yes':
            # Remember consent if policy is 'once'
            pol = db.query(ClientPolicy).filter_by(client_id=client.client_id).first()
            if pol and (pol.consent_policy or 'once') == 'once':
                def _norm(s: str) -> str:
                    return ' '.join(sorted(scope_to_list(s or '')))
                req_obj = getattr(grant, 'request', None)
                payload = getattr(req_obj, 'payload', None)
                scope_str = None
                if payload is not None:
                    scope_str = getattr(payload, 'scope', None)
                    if scope_str is None and isinstance(payload, dict):
                        scope_str = payload.get('scope', '')
                if scope_str is None:
                    scope_str = getattr(req_obj, 'scope', '') or ''
                db.add(RememberedConsent(user_id=user.id, client_id=client.client_id, scope=_norm(scope_str)))
                db.commit()
            return auth_server.create_authorization_response(grant_user=user)
        return auth_server.create_authorization_response(grant_user=None)
    finally:
        db.close()

# ----------------------
# OAuth2: /token
# ----------------------
@app.route('/token', methods=['POST'])
def issue_token():
    return auth_server.create_token_response()

# ----------------------
# Protected API example
# ----------------------
@app.route('/userinfo')
@require_oauth('profile')
def userinfo():
    u = current_token.user
    return jsonify({
        'sub': u.id,
        'preferred_username': u.username,
        'email': u.email,
    })

# ----------------------
# OIDC Discovery & JWKS
# ----------------------
@app.route('/.well-known/openid-configuration')
def openid_config():
    # Dynamic scopes from DB if present
    db = SessionLocal()
    try:
        scopes_supported = [s.name for s in db.query(Scope).all()]
        if not scopes_supported:
            scopes_supported = ['openid', 'profile', 'email', 'offline_access']
    finally:
        db.close()
    return jsonify({
        'issuer': _issuer(),
        'authorization_endpoint': url_for('authorize', _external=True),
        'token_endpoint': url_for('issue_token', _external=True),
        'userinfo_endpoint': url_for('userinfo', _external=True),
        'jwks_uri': url_for('jwks', _external=True),
        'end_session_endpoint': url_for('end_session', _external=True),
        'revocation_endpoint': url_for('revoke_token', _external=True),
        'introspection_endpoint': url_for('introspect_token', _external=True),
        'scopes_supported': scopes_supported,
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code', 'refresh_token', 'client_credentials'],
        'token_endpoint_auth_methods_supported': ['none', 'client_secret_basic', 'client_secret_post'],
        'id_token_signing_alg_values_supported': ['RS256'],
        'subject_types_supported': ['public'],
    })

@app.route('/.well-known/jwks.json')
def jwks():
    db = SessionLocal()
    try:
        rows = db.query(OIDCKey).all()
        keys = [json.loads(r.public_jwk) for r in rows]
        return jsonify({'keys': keys})
    finally:
        db.close()

@app.route('/health')
def health():
    # Lightweight readiness/liveness probe
    return jsonify({'status': 'ok'}), 200

# ----------------------
# Token Revocation & Introspection
# ----------------------
def _authenticate_client_for_management():
    """Authenticate client via Basic or POST body; allow public clients (no secret)."""
    auth = request.headers.get('Authorization', '')
    client_id = None
    client_secret = None
    if auth.startswith('Basic '):
        try:
            raw = base64.b64decode(auth.split(' ', 1)[1]).decode()
            client_id, client_secret = raw.split(':', 1)
        except Exception:
            pass
    if not client_id:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    if not client_id:
        abort(401)
    client = query_client(client_id)
    if not client:
        abort(401)
    # If client has a secret configured, verify it; else allow public client
    if client.client_secret:
        if not client.check_client_secret(client_secret):
            abort(401)
    return client

@app.route('/revoke', methods=['POST'])
def revoke_token():
    client = _authenticate_client_for_management()
    tok_str = request.form.get('token')
    hint = (request.form.get('token_type_hint') or '').lower()
    db = SessionLocal()
    try:
        tok = None
        if hint == 'refresh_token':
            tok = db.query(OAuth2Token).filter_by(refresh_token=tok_str).first()
        elif hint == 'access_token':
            tok = db.query(OAuth2Token).filter_by(access_token=tok_str).first()
        if not tok:
            tok = db.query(OAuth2Token).filter(
                (OAuth2Token.access_token == tok_str) | (OAuth2Token.refresh_token == tok_str)
            ).first()
        if tok and tok.client_id == client.client_id:
            tok.revoked = True
            db.add(tok)
            db.commit()
        # Per RFC7009, always return 200 even if token is unknown
        return ('', 200)
    finally:
        db.close()

@app.route('/introspect', methods=['POST'])
def introspect_token():
    client = _authenticate_client_for_management()
    tok_str = request.form.get('token')
    hint = (request.form.get('token_type_hint') or '').lower()
    db = SessionLocal()
    try:
        tok = None
        if hint == 'refresh_token':
            tok = db.query(OAuth2Token).filter_by(refresh_token=tok_str).first()
        elif hint == 'access_token':
            tok = db.query(OAuth2Token).filter_by(access_token=tok_str).first()
        if not tok:
            tok = db.query(OAuth2Token).filter(
                (OAuth2Token.access_token == tok_str) | (OAuth2Token.refresh_token == tok_str)
            ).first()
        if not tok or tok.client_id != client.client_id:
            return jsonify({'active': False})
        now = int(datetime.now(timezone.utc).timestamp())
        exp = tok.issued_at + (tok.expires_in or 0)
        active = (not tok.revoked) and (now < exp)
        data = {
            'active': active,
            'client_id': tok.client_id,
            'token_type': tok.token_type,
            'scope': tok.scope or '',
            'exp': exp,
            'iat': tok.issued_at,
        }
        if tok.user:
            data.update({'sub': str(tok.user.id), 'username': tok.user.username})
        return jsonify(data)
    finally:
        db.close()

# ----------------------
# Dev helpers: seed users/clients
# ----------------------
@app.route('/dev/seed')
def dev_seed():
    # Gate behind ENABLE_DEV_ENDPOINTS and require admin token when enabled
    if os.environ.get('ENABLE_DEV_ENDPOINTS', '').lower() not in ('1','true','yes','on'):
        abort(404)
    _require_admin()
    db = SessionLocal()
    # users
    reset = (request.args.get('reset') or '').lower() in ('1','true','yes','on')
    u_alice = db.query(User).filter_by(username='alice').first()
    if not u_alice:
        db.add(User(username='alice', email='alice@example.com', password_hash=generate_password_hash('alice')))
    elif reset:
        u_alice.password_hash = generate_password_hash('alice')
        db.add(u_alice)
    u_bob = db.query(User).filter_by(username='bob').first()
    if not u_bob:
        db.add(User(username='bob', email='bob@example.com', password_hash=generate_password_hash('bob')))
    elif reset:
        u_bob.password_hash = generate_password_hash('bob')
        db.add(u_bob)

    # public PKCE client
    existing = db.query(OAuth2Client).filter_by(client_id='demo-web').first()
    if not existing:
        c = OAuth2Client(
            client_id='demo-web',
            client_secret=None,
            client_name='Demo Web App',
            client_uri='http://localhost:3000',
            logo_uri='',
            grant_types='authorization_code refresh_token',
            response_types='code',
            scope='openid profile email files.read offline_access',
            redirect_uris='http://127.0.0.1:3000/callback http://localhost:3000/callback',
            token_endpoint_auth_method='none',
            require_consent=True,
        )
        db.add(c)
    else:
        # Update existing client to ensure refresh + offline_access are enabled
        if existing.grant_types:
            gts = set(existing.grant_types.split())
            gts.update({'authorization_code', 'refresh_token', 'client_credentials'})
            existing.grant_types = ' '.join(sorted(gts))
        else:
            existing.grant_types = 'authorization_code refresh_token client_credentials'
        if existing.scope:
            scs = set(existing.scope.split())
            scs.update({'openid', 'profile', 'email', 'offline_access'})
            existing.scope = ' '.join(sorted(scs))
        else:
            existing.scope = 'openid profile email offline_access'
        if not existing.redirect_uris or 'localhost:3000/callback' not in existing.redirect_uris:
            existing.redirect_uris = 'http://127.0.0.1:3000/callback http://localhost:3000/callback'
        existing.token_endpoint_auth_method = 'none'
    # Seed core OIDC scopes only (no app-specific hardcoding)
    def upsert_scope(name, desc):
        s = db.query(Scope).filter_by(name=name).first()
        if s:
            s.description = desc
        else:
            db.add(Scope(name=name, description=desc, claims=json.dumps([])))
    core_scopes = [
        ('openid','Sign you in'),
        ('profile','Read your basic profile'),
        ('email','Read your email address'),
        ('offline_access','Get a refresh token for offline access')
    ]
    for name, desc in core_scopes:
        upsert_scope(name, desc)

    # Seed a default client policy for demo-web (dev convenience)
    pol = db.query(ClientPolicy).filter_by(client_id='demo-web').first()
    if not pol:
        pol = ClientPolicy(
            client_id='demo-web',
            allowed_scopes='openid profile email offline_access',
            default_scopes='openid profile email offline_access',
            post_logout_redirect_uris='http://localhost:3000/',
            require_pkce=True,
            consent_policy='once',
            access_token_lifetime=3600,
            refresh_token_ttl_days=30,
            token_format='opaque'
        )
        db.add(pol)
    db.commit()
    db.close()
    return "Seeded users and client.\nUsers: alice/alice, bob/bob\nClient: demo-web (PKCE public)\n(Use ?reset=1 to reset demo user passwords)"

 

# ----------------------
# PKCE helper (dev)
# ----------------------
@app.route('/dev/pkce')
def dev_pkce():
    # Gate behind ENABLE_DEV_ENDPOINTS and require admin token when enabled
    if os.environ.get('ENABLE_DEV_ENDPOINTS', '').lower() not in ('1','true','yes','on'):
        abort(404)
    _require_admin()
    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip('=')
    challenge = base64.urlsafe_b64encode(__import__('hashlib').sha256(verifier.encode()).digest()).decode().rstrip('=')
    return jsonify({'code_verifier': verifier, 'code_challenge': challenge, 'method': 'S256'})

# ----------------------
# Startup
# ----------------------
if __name__ == '__main__':
    # Ensure some seed exists on first run
    with app.test_request_context():
        pass

    host = '127.0.0.1'
    port = 8000
    base = f"http://{host}:{port}"
    print(f"""
Quick test steps:
  1) Open {base}/dev/seed to create demo users/client
  2) GET {base}/dev/pkce to obtain verifier+challenge
  3) Open /authorize URL in a browser, for example:
     {base}/authorize?client_id=demo-web&response_type=code&scope=openid%20profile%20email&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_challenge_method=S256&code_challenge=<CHALLENGE>
  4) Login as alice/alice, approve consent, copy the ?code=...
  5) Exchange code with curl:
     curl -X POST {base}/token \
          -H 'Content-Type: application/x-www-form-urlencoded' \
          -d 'grant_type=authorization_code' \
          -d 'client_id=demo-web' \
          -d 'code_verifier=<VERIFIER>' \
          -d 'code=<CODE_FROM_CALLBACK>' \
          -d 'redirect_uri=http://localhost:3000/callback'
  6) Call a protected API:
     curl {base}/userinfo -H 'Authorization: Bearer <access_token>'
""")
    app.run(debug=True, host=host, port=port)
