"""Orquestación de flujos OAuth.

Coordina los proveedores (capa 2), el servidor local de redirección que
captura el código de autorización, el navegador y el almacén de credenciales
(capa 3).
"""

from __future__ import annotations

import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from .config import OAuthConfig
from .credentials import OAuthCredentials, CredentialsStore, PlatformCredentials
from .providers.kick import KickOAuthProvider
from .providers.twitch import TwitchOAuthProvider


class _CallbackHandler(BaseHTTPRequestHandler):
    """Manejador HTTP que captura el código de autorización del callback."""

    result: Dict[str, str] = {}
    done = threading.Event()

    def do_GET(self) -> None:  # noqa: N802 (nombre impuesto por BaseHTTPRequestHandler)
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        _CallbackHandler.result = {
            "code": (query.get("code") or [None])[0],
            "error": (query.get("error") or [None])[0],
            "state": (query.get("state") or [None])[0],
            "path": parsed.path,
        }
        _CallbackHandler.done.set()

        body = (
            b"<html><body><h1>Autorizaci&oacute;n recibida</h1>"
            b"<p>Puedes cerrar esta pesta&ntilde;a y volver a la aplicaci&oacute;n.</p>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # silencia logs del servidor
        pass


class OAuthManager:
    """Gestiona el inicio de sesión OAuth de Twitch y Kick."""

    def __init__(
        self,
        config: OAuthConfig,
        store: Optional[CredentialsStore] = None,
    ) -> None:
        self.config = config
        self.store = store or CredentialsStore()
        self._providers: dict = {}
        self._build_providers()

    # ------------------------------------------------------------------ #
    # Proveedores
    # ------------------------------------------------------------------ #
    def _build_providers(self) -> None:
        if self.config.twitch.enabled and self.config.twitch.client_id:
            self._providers["twitch"] = TwitchOAuthProvider(
                client_id=self.config.twitch.client_id,
                client_secret=self.config.twitch.client_secret,
                redirect_uri=self.config.twitch.redirect_uri,
                scopes=self.config.twitch.scopes,
            )
        if self.config.kick.enabled and self.config.kick.client_id:
            self._providers["kick"] = KickOAuthProvider(
                client_id=self.config.kick.client_id,
                client_secret=self.config.kick.client_secret,
                redirect_uri=self.config.kick.redirect_uri,
                scopes=self.config.kick.scopes,
            )

    def provider(self, platform: str):
        return self._providers.get(platform)

    def available_platforms(self) -> list:
        return list(self._providers.keys())

    # ------------------------------------------------------------------ #
    # Flujo de login
    # ------------------------------------------------------------------ #
    def login(
        self,
        platform: str,
        open_browser: bool = True,
        start_server: bool = True,
        timeout_seconds: int = 120,
    ) -> OAuthCredentials:
        """Ejecuta el flujo OAuth completo para una plataforma.

        Devuelve las credenciales actualizadas y las persiste en el almacén.
        """
        provider = self.provider(platform)
        if provider is None:
            raise ValueError(
                f"Plataforma '{platform}' no configurada o no habilitada."
            )

        state = self._generate_state()
        auth_url = provider.get_authorization_url(state)

        code = self._wait_for_code(
            platform=platform,
            expected_state=state,
            auth_url=auth_url,
            open_browser=open_browser,
            start_server=start_server,
            timeout_seconds=timeout_seconds,
        )

        token_data = provider.exchange_code(code)
        credentials = self._build_credentials(platform, provider, token_data)
        self.store.save(credentials)

        # Escribir .env.oauth con la estructura exacta del siguiente módulo
        from .credentials import write_next_module_env

        env_content = write_next_module_env(
            credentials,
            path=".env.oauth",
            twitch_client_id=self.config.twitch.client_id,
            kick_public_key_pem=self.config.kick.public_key_pem,
        )
        print("\n" + env_content)
        return credentials

    def _wait_for_code(
        self,
        platform: str,
        expected_state: str,
        auth_url: str,
        open_browser: bool,
        start_server: bool,
        timeout_seconds: int,
    ) -> str:
        path = f"/callback/{platform}"

        if start_server:
            server = HTTPServer(
                (self.config.local_host, self.config.local_port), _CallbackHandler
            )
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
        else:
            server = None

        try:
            if open_browser:
                webbrowser.open(auth_url)

            _CallbackHandler.done.clear()
            _CallbackHandler.result = {}
            got = _CallbackHandler.done.wait(timeout=timeout_seconds)
            if not got:
                raise TimeoutError(
                    f"Tiempo de espera agotado esperando el código de {platform}"
                )

            result = _CallbackHandler.result
            if result.get("error"):
                raise RuntimeError(
                    f"Error de autorización en {platform}: {result['error']}"
                )
            if result.get("state") != expected_state:
                raise RuntimeError("El state devuelto no coincide (posible CSRF).")
            if result.get("path") != path:
                # El callback llegó a una ruta distinta; aún así usamos el código si hay uno.
                pass
            code = result.get("code")
            if not code:
                raise RuntimeError(f"No se recibió código de autorización de {platform}.")
            return code
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()

    # ------------------------------------------------------------------ #
    # Construcción de credenciales
    # ------------------------------------------------------------------ #
    def _build_credentials(
        self, platform: str, provider, token_data: dict
    ) -> OAuthCredentials:
        current = self.store.load()
        plat_creds = provider.create_credentials(token_data)

        # Marca de expiración absoluta
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        if plat_creds.expires_in:
            plat_creds.expires_at = (
                now + timedelta(seconds=plat_creds.expires_in)
            ).isoformat()

        updated = OAuthCredentials(
            twitch=current.twitch,
            kick=current.kick,
            twitch_bot_user_id=current.twitch_bot_user_id,
            twitch_broadcaster_ids=current.twitch_broadcaster_ids,
            kick_broadcaster_ids=current.kick_broadcaster_ids,
        )
        if platform == "twitch":
            updated.twitch = plat_creds
            # Twitch no devuelve user_id en el token; lo consultamos en su API
            user_id = self._fetch_twitch_user_id(
                plat_creds.access_token, self.config.twitch.client_id
            )
            updated.twitch_bot_user_id = user_id
            updated.twitch_broadcaster_ids = user_id
        else:
            updated.kick = plat_creds
            # Kick no devuelve broadcaster_id en el token; lo consultamos en su API
            broadcaster_id = self._fetch_kick_broadcaster_id(plat_creds.access_token)
            updated.kick_broadcaster_ids = broadcaster_id
        return updated

    def _fetch_twitch_user_id(self, access_token: str, client_id: str) -> str:
        """Consulta Twitch Helix para obtener el ID del usuario autenticado."""
        import requests

        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Client-Id": client_id,
            }
            resp = requests.get(
                "https://api.twitch.tv/helix/users",
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            users = data.get("data", [])
            if users:
                return str(users[0].get("id", ""))
        except Exception:  # noqa: BLE001 - no fallamos el login por esto
            pass
        return ""

    def _fetch_kick_broadcaster_id(self, access_token: str) -> str:
        """Consulta la API de Kick para obtener el broadcaster_id del usuario.

        Endpoint oficial: GET https://api.kick.com/public/v1/users
        Si no se pasan IDs, devuelve la información del usuario autenticado.
        """
        import requests

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        # Endpoint oficial de Kick para obtener el usuario autenticado.
        # Sin parámetros de query, devuelve al usuario del token.
        endpoints = ["https://api.kick.com/public/v1/users"]

        for url in endpoints:
            try:
                resp = requests.get(url, headers=headers, timeout=15)
                if resp.status_code >= 400:
                    continue
                data = resp.json()

                # La respuesta oficial es: {"data": [{"user_id": 123, ...}], "message": "..."}
                users = data.get("data") or []
                if users:
                    user_id = (
                        users[0].get("user_id")
                        or users[0].get("id")
                        or users[0].get("broadcaster_id")
                        or ""
                    )
                    if user_id:
                        return str(user_id)

                # Fallback: buscar en nivel raíz por si la estructura cambia
                for key in ("id", "user_id", "broadcaster_id"):
                    val = data.get(key)
                    if val:
                        return str(val)

            except Exception:  # noqa: BLE001 - probamos el siguiente endpoint
                pass

        return ""

    @staticmethod
    def _generate_state() -> str:
        import secrets

        return secrets.token_urlsafe(32)
