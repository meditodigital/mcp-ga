import base64
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from starlette.applications import Starlette
from starlette.testclient import TestClient

from analytics_mcp.app_config import (
    ANALYTICS_READONLY_SCOPE,
    load_app_config,
    remote_auth_enabled,
)
from analytics_mcp.oauth_server import _s256, _sign, oauth_routes
from analytics_mcp.token_store import Principal, TokenStore


def _fernet_key() -> str:
    return Fernet.generate_key().decode("ascii")


def _remote_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "MCP_TRANSPORT": "streamable-http",
        "PUBLIC_BASE_URL": "https://ga.example.com",
        "GOOGLE_CLIENT_ID": "google-client",
        "GOOGLE_CLIENT_SECRET": "google-secret",
        "GOOGLE_HOSTED_DOMAIN": "meditodigital.com",
        "MCP_OAUTH_CLIENT_ID": "mcp-client",
        "MCP_OAUTH_CLIENT_SECRET": "mcp-secret",
        "MCP_OAUTH_REDIRECT_URIS": "https://claude.ai/api/mcp/auth_callback",
        "DATABASE_URL": "sqlite:///:memory:",
        "APP_ENCRYPTION_KEY": _fernet_key(),
        "SESSION_COOKIE_SECRET": base64.urlsafe_b64encode(
            os.urandom(32)
        ).decode("ascii"),
    }
    env.update(overrides or {})
    return env


class TestRemoteAuth(unittest.TestCase):
    def test_remote_auth_enabled_by_streamable_transport(self):
        self.assertTrue(
            remote_auth_enabled({"MCP_TRANSPORT": "streamable-http"})
        )
        self.assertFalse(remote_auth_enabled({"MCP_TRANSPORT": "stdio"}))

    def test_config_defaults_to_analytics_readonly_scope(self):
        config = load_app_config(_remote_env())

        self.assertIn(ANALYTICS_READONLY_SCOPE, config.google.scopes)
        self.assertEqual(config.session.cookie_name, "ga_session")

    def test_token_store_uses_ga_prefixed_tables(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "auth.db")
            store = TokenStore(f"sqlite:///{db_path}", _fernet_key())
            store.init()

            with sqlite3.connect(db_path) as conn:
                names = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
                    )
                }

        self.assertTrue(
            {
                "ga_google_auth_flows",
                "ga_google_credentials",
                "ga_oauth_authorization_codes",
                "ga_oauth_tokens",
                "ga_oauth_tokens_refresh_idx",
                "ga_oauth_tokens_subject_idx",
            }.issubset(names)
        )
        self.assertNotIn("google_auth_flows", names)
        self.assertNotIn("google_credentials", names)
        self.assertNotIn("oauth_authorization_codes", names)
        self.assertNotIn("oauth_tokens", names)

    def test_stored_credentials_use_current_client_secret(self):
        from analytics_mcp.auth_context import credentials_from_stored

        config = load_app_config(_remote_env())
        stored = json.dumps(
            {
                "token": "access",
                "refresh_token": "refresh",
                "client_id": "old-id",
                "client_secret": "old-secret",
            }
        )
        credentials = credentials_from_stored(stored, ["openid"], config)
        self.assertEqual(credentials.client_id, config.google.client_id)
        self.assertEqual(
            credentials.client_secret, config.google.client_secret
        )
        self.assertEqual(credentials.refresh_token, "refresh")

    def test_token_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TokenStore(
                f"sqlite:///{os.path.join(tmpdir, 'auth.db')}", _fernet_key()
            )
            store.init()
            principal = Principal(
                "sub-1", "user@meditodigital.com", "meditodigital.com", "User"
            )
            credentials = json.dumps(
                {
                    "token": "access",
                    "refresh_token": "refresh",
                    "client_id": "google-client",
                    "client_secret": "google-secret",
                }
            )

            store.store_google_credentials(
                principal, credentials, [ANALYTICS_READONLY_SCOPE]
            )
            pair = store.create_token_pair(
                "mcp-client", principal, ["mcp"], 60, 120
            )
            validation = store.validate_access_token(pair.access_token)
            rotated = store.rotate_refresh_token(
                pair.refresh_token, "mcp-client", 60, 120
            )

        self.assertIsNotNone(validation)
        assert validation is not None
        self.assertEqual(validation.principal.email, "user@meditodigital.com")
        self.assertIsNotNone(rotated)

    def test_oauth_code_flow_uses_workspace_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = _remote_env(
                {"DATABASE_URL": f"sqlite:///{os.path.join(tmpdir, 'auth.db')}"}
            )
            config = load_app_config(env)
            store = TokenStore(config.database_url, config.encryption_key)
            store.init()
            principal = Principal(
                "sub-1", "user@meditodigital.com", "meditodigital.com", "User"
            )
            store.store_google_credentials(
                principal,
                json.dumps({"refresh_token": "refresh"}),
                [ANALYTICS_READONLY_SCOPE],
            )
            verifier = "verifier-value"
            query = (
                "/oauth/authorize?response_type=code&client_id=mcp-client"
                "&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback"
                f"&code_challenge={_s256(verifier)}&code_challenge_method=S256"
                "&scope=mcp&state=abc"
            )
            cookie = _sign(
                {
                    "sub": principal.subject,
                    "email": principal.email,
                    "hd": principal.hosted_domain,
                    "name": principal.display_name,
                    "exp": 9999999999,
                },
                config.session.cookie_secret,
            )
            app = Starlette(routes=oauth_routes(config, store))

            with TestClient(app) as client:
                client.cookies.set(config.session.cookie_name, cookie)
                response = client.get(query, follow_redirects=False)
                code = (
                    response.headers["location"]
                    .split("code=", 1)[1]
                    .split("&", 1)[0]
                )
                token_response = client.post(
                    "/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": "mcp-client",
                        "client_secret": "mcp-secret",
                        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                        "code": code,
                        "code_verifier": verifier,
                    },
                )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(token_response.status_code, 200)
        self.assertEqual(token_response.json()["token_type"], "Bearer")

    def test_web_app_exposes_mcp_route(self):
        from analytics_mcp.auth_context import get_app_config, get_token_store
        from analytics_mcp.coordinator import app as mcp_app
        from analytics_mcp.web_app import create_web_app

        with tempfile.TemporaryDirectory() as tmpdir:
            env = _remote_env(
                {"DATABASE_URL": f"sqlite:///{os.path.join(tmpdir, 'auth.db')}"}
            )
            get_app_config.cache_clear()
            get_token_store.cache_clear()
            with patch.dict(os.environ, env, clear=False):
                app = create_web_app(mcp_app)

        get_app_config.cache_clear()
        get_token_store.cache_clear()
        self.assertTrue(
            any(getattr(route, "path", None) == "/mcp" for route in app.routes)
        )


if __name__ == "__main__":
    unittest.main()
