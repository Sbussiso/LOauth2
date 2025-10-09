#!/usr/bin/env python3
"""Add opensentry-device client to the OAuth2 server database."""
import os
import json
import sys

# Set database URL
os.environ['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'sqlite:///oauth.db')

from server import SessionLocal, OAuth2Client

# Create a session
db = SessionLocal()

# Check if client exists
existing = db.query(OAuth2Client).filter_by(client_id='opensentry-device').first()

# Redirect URIs as space-separated string (as expected by OAuth2 server)
redirect_uris = 'http://localhost:5000/oauth2/callback http://127.0.0.1:5000/oauth2/callback'
# Scope as space-separated string
scope = 'openid profile email offline_access'

if existing:
    print("Client 'opensentry-device' already exists. Updating...")
    existing.client_secret = None
    existing.client_name = 'OpenSentry Device'
    existing.redirect_uris = redirect_uris
    existing.scope = scope
    existing.grant_types = 'authorization_code refresh_token'
    existing.response_types = 'code'
    existing.token_endpoint_auth_method = 'none'
    existing.require_consent = True
    db.commit()
    print("✓ Client 'opensentry-device' updated successfully")
else:
    print("Creating new client 'opensentry-device'...")
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
    print("✓ Client 'opensentry-device' created successfully")

print("\nClient details:")
client = db.query(OAuth2Client).filter_by(client_id='opensentry-device').first()
print(f"  Client ID: {client.client_id}")
print(f"  Client Name: {client.client_name}")
print(f"  Auth Method: {client.token_endpoint_auth_method}")
print(f"  Grant Types: {client.grant_types}")
print(f"  Redirect URIs: {client.redirect_uris}")
print(f"  Scope: {client.scope}")
print(f"  Client Secret: {client.client_secret}")

db.close()
