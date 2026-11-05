"""Pruebas del módulo OAuth.

Se ejecutan sin red ni credenciales reales: las peticiones HTTP se mockean.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from oauth_module.config import OAuthConfig, load_config, TwitchConfig, KickConfig
from oauth_module.credentials import (
    OAuthCredentials,
    PlatformCredentials,
    CredentialsStore,
)
from oauth_module.providers.kick import KickOAuthProvider
from oauth_module.providers.twitch import TwitchOAuthProvider


class FakeResponse:
    """Respuesta HTTP falsa."""

    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._data


class TestPKCE(unittest.TestCase):
    """Pruebas del flujo PKCE de Kick."""

    def test_code_verifier_length(self):
        verifier = KickOAuthProvider.generate_code_verifier()
        self.assertTrue(43 <= len(verifier) <= 128)
        # Solo caracteres seguros para URL
        self.assertTrue(all(c.isalnum() or c in "-._~" for c in verifier))

    def test_code_challenge_is_sha256_base64url(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJ51p1x8w"
        challenge = KickOAuthProvider.generate_code_challenge(verifier)
        self.assertEqual(len(challenge), 43)
        self.assertNotIn("=", challenge)

    def test_authorization_url_includes_challenge(self):
        provider = KickOAuthProvider(
            client_id="kick_client_id",
            client_secret="kick_secret",
            redirect_uri="http://localhost:8765/callback/kick",
            scopes=["user:read", "chat:write"],
        )
        url = provider.get_authorization_url(state="abc123")
        self.assertIn("https://id.kick.com/oauth/authorize", url)
        self.assertIn("response_type=code", url)
        self.assertIn("code_challenge_method=S256", url)
        self.assertIn("code_challenge=", url)
        self.assertIn("scope=user%3Aread+chat%3Awrite", url)
        # Debe haber guardado el verifier para el intercambio
        self.assertIsNotNone(provider.code_verifier)


class TestTwitch(unittest.TestCase):
    """Pruebas del proveedor de Twitch (Authorization Code)."""

    def test_authorization_url(self):
        provider = TwitchOAuthProvider(
            client_id="twitch_client_id",
            client_secret="twitch_secret",
            redirect_uri="http://localhost:8765/callback/twitch",
            scopes=["user:read:email", "chat:edit"],
        )
        url = provider.get_authorization_url(state="xyz")
        self.assertIn("https://id.twitch.tv/oauth2/authorize", url)
        self.assertIn("response_type=code", url)
        self.assertIn("client_id=twitch_client_id", url)
        self.assertIn("scope=user%3Aread%3Aemail+chat%3Aedit", url)
        self.assertIn("state=xyz", url)

    def test_exchange_code(self):
        provider = TwitchOAuthProvider(
            client_id="cid",
            client_secret="secret",
            redirect_uri="http://localhost:8765/callback/twitch",
            scopes=[],
        )
        fake_session = MagicMock()
        fake_session.post.return_value = FakeResponse(
            {
                "access_token": "at_123",
                "refresh_token": "rt_456",
                "expires_in": 3600,
                "token_type": "bearer",
                "scope": "user:read:email",
            }
        )
        provider.session = fake_session

        data = provider.exchange_code("auth_code_999")
        self.assertEqual(data["access_token"], "at_123")

        # Verificar que se envió client_secret (OAuth oficial, no PKCE)
        _, kwargs = fake_session.post.call_args
        body = kwargs["data"]
        self.assertEqual(body["client_id"], "cid")
        self.assertEqual(body["client_secret"], "secret")
        self.assertEqual(body["grant_type"], "authorization_code")
        self.assertNotIn("code_verifier", body)

    def test_create_credentials(self):
        provider = TwitchOAuthProvider(
            client_id="cid",
            client_secret="secret",
            redirect_uri="http://localhost:8765/callback/twitch",
            scopes=[],
        )
        creds = provider.create_credentials(
            {
                "access_token": "at_123",
                "refresh_token": "rt_456",
                "expires_in": 3600,
                "token_type": "bearer",
                "scope": "chat:edit",
            }
        )
        self.assertEqual(creds.access_token, "at_123")
        self.assertEqual(creds.refresh_token, "rt_456")
        self.assertEqual(creds.scope, "chat:edit")
        self.assertEqual(creds.expires_in, 3600)
        self.assertFalse(creds.is_expired)


class TestKickExchange(unittest.TestCase):
    """Pruebas del intercambio de código de Kick con code_verifier."""

    def test_exchange_code_includes_verifier(self):
        provider = KickOAuthProvider(
            client_id="cid",
            client_secret="secret",
            redirect_uri="http://localhost:8765/callback/kick",
            scopes=["user:read"],
        )
        provider.get_authorization_url(state="s")  # genera verifier

        fake_session = MagicMock()
        fake_session.post.return_value = FakeResponse(
            {"access_token": "kick_at", "expires_in": 7200, "token_type": "bearer"}
        )
        provider.session = fake_session

        data = provider.exchange_code("kick_code")
        self.assertEqual(data["access_token"], "kick_at")

        _, kwargs = fake_session.post.call_args
        body = kwargs["data"]
        self.assertEqual(body["code"], "kick_code")
        self.assertEqual(body["grant_type"], "authorization_code")
        self.assertEqual(body["code_verifier"], provider.code_verifier)
        self.assertEqual(body["client_secret"], "secret")  # Kick requiere client_secret


class TestCredentialsStore(unittest.TestCase):
    """Pruebas de carga/guardado del archivo de credenciales (capa 3)."""

    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "credentials.json")
            store = CredentialsStore(path)

            creds = OAuthCredentials()
            creds.twitch.access_token = "twitch_at"
            creds.twitch.refresh_token = "twitch_rt"
            creds.twitch.scope = "chat:edit"
            creds.twitch_bot_user_id = "bot_123"
            creds.kick.access_token = "kick_at"
            creds.kick.scope = "user:read"
            creds.kick_broadcaster_ids = "b_1,b_2"

            store.save(creds)
            loaded = store.load()

            self.assertEqual(loaded.twitch.access_token, "twitch_at")
            self.assertEqual(loaded.twitch.refresh_token, "twitch_rt")
            self.assertEqual(loaded.twitch.scope, "chat:edit")
            self.assertEqual(loaded.twitch_bot_user_id, "bot_123")
            self.assertEqual(loaded.kick.access_token, "kick_at")
            self.assertEqual(loaded.kick.scope, "user:read")
            self.assertEqual(loaded.kick_broadcaster_ids, "b_1,b_2")

    def test_missing_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "no_existe.json")
            store = CredentialsStore(path)
            creds = store.load()
            self.assertEqual(creds.twitch.access_token, "")
            self.assertEqual(creds.kick.access_token, "")

    def test_to_dict_from_dict(self):
        creds = OAuthCredentials()
        creds.kick.access_token = "tok"
        d = creds.to_dict()
        self.assertEqual(d["kick"]["access_token"], "tok")
        restored = OAuthCredentials.from_dict(d)
        self.assertEqual(restored.kick.access_token, "tok")


class TestConfig(unittest.TestCase):
    """Pruebas de carga de configuración."""

    def test_load_from_env_example(self):
        env_file = os.path.join(os.path.dirname(__file__), "..", ".env.example")
        env_file = os.path.abspath(env_file)
        config = load_config(env_file)
        self.assertTrue(config.twitch.enabled)
        self.assertTrue(config.kick.enabled)
        self.assertEqual(config.kick.webhook_addr, "0.0.0.0:8080")
        self.assertEqual(config.kick.webhook_path, "/kick/webhook")
        self.assertEqual(config.local_port, 8765)
        self.assertIn("user:read:email", config.twitch.scopes)
        self.assertIn("chat:write", config.kick.scopes)

    def test_defaults_when_missing(self):
        # Sin archivo ni variables de entorno, usa valores por defecto.
        config = load_config("/tmp/opencode/definitely_not_exists.env")
        self.assertFalse(config.twitch.enabled)
        self.assertFalse(config.kick.enabled)
        self.assertEqual(config.twitch.client_id, "")
        self.assertEqual(config.kick.verify_signatures, True)
        self.assertEqual(config.kick.send_as, "bot")


class TestManagerBuildProviders(unittest.TestCase):
    """Pruebas del gestor: construcción de proveedores desde config."""

    def test_builds_only_enabled_providers(self):
        config = OAuthConfig(
            twitch=TwitchConfig(
                enabled=True,
                client_id="t_id",
                client_secret="t_secret",
                redirect_uri="http://localhost:8765/callback/twitch",
                scopes=["chat:read"],
            ),
            kick=KickConfig(enabled=False),
        )
        from oauth_module.manager import OAuthManager

        manager = OAuthManager(config)
        self.assertEqual(manager.available_platforms(), ["twitch"])
        self.assertIsInstance(manager.provider("twitch"), TwitchOAuthProvider)
        self.assertIsNone(manager.provider("kick"))

    def test_login_raises_for_unknown_platform(self):
        config = OAuthConfig()
        from oauth_module.manager import OAuthManager

        manager = OAuthManager(config)
        with self.assertRaises(ValueError):
            manager.login("twitch")


if __name__ == "__main__":
    unittest.main()
