"""Servidor gRPC para comunicación en tiempo real con el siguiente módulo.

Expone las credenciales OAuth de Twitch y Kick a través de gRPC para que
el siguiente módulo pueda solicitar tokens, refrescarlos y obtener credenciales
sin depender de archivos .env estáticos.
"""

from __future__ import annotations

import grpc
from concurrent import futures
from datetime import datetime, timezone
from typing import Optional

from oauth_module.proto import oauth_pb2, oauth_pb2_grpc
from oauth_module.manager import OAuthManager
from oauth_module.config import load_config


def _remaining_seconds(expires_at: Optional[str]) -> int:
    """Calcula los segundos restantes hasta la expiración absoluta.

    Devuelve 0 si no hay fecha, si ya expiró o si la fecha es inválida.
    """
    if not expires_at:
        return 0
    try:
        expires = datetime.fromisoformat(expires_at)
        now = datetime.now(timezone.utc)
        return max(0, int((expires - now).total_seconds()))
    except ValueError:
        return 0


class OAuthServiceServicer(oauth_pb2_grpc.OAuthServiceServicer):
    """Implementación del servicio gRPC de OAuth."""

    def __init__(self, manager: OAuthManager) -> None:
        self.manager = manager

    def GetToken(self, request, context):
        platform = request.platform.lower()
        provider = self.manager.provider(platform)
        if provider is None:
            return oauth_pb2.TokenResponse(
                platform=platform,
                success=False,
                error=f"Plataforma '{platform}' no configurada o no habilitada.",
            )

        store = self.manager.store
        creds = store.load()
        if platform == "twitch":
            pc = creds.twitch
        else:
            pc = creds.kick

        return oauth_pb2.TokenResponse(
            platform=platform,
            access_token=pc.access_token,
            refresh_token=pc.refresh_token,
            token_type=pc.token_type,
            expires_in=pc.expires_in or 0,
            scope=pc.scope,
            success=True,
            error="",
        )

    def RefreshToken(self, request, context):
        platform = request.platform.lower()
        provider = self.manager.provider(platform)
        if provider is None:
            return oauth_pb2.TokenResponse(
                platform=platform,
                success=False,
                error=f"Plataforma '{platform}' no configurada o no habilitada.",
            )

        store = self.manager.store
        creds = store.load()
        if platform == "twitch":
            pc = creds.twitch
        else:
            pc = creds.kick

        if not pc.refresh_token:
            return oauth_pb2.TokenResponse(
                platform=platform,
                success=False,
                error="No hay refresh_token disponible para esta plataforma.",
            )

        # Intercambiar refresh_token por nuevo access_token
        try:
            import requests

            if platform == "twitch":
                token_url = "https://id.twitch.tv/oauth2/token"
                data = {
                    "grant_type": "refresh_token",
                    "refresh_token": pc.refresh_token,
                    "client_id": self.manager.config.twitch.client_id,
                    "client_secret": self.manager.config.twitch.client_secret,
                }
            else:
                token_url = "https://id.kick.com/oauth/token"
                data = {
                    "grant_type": "refresh_token",
                    "refresh_token": pc.refresh_token,
                    "client_id": self.manager.config.kick.client_id,
                    "client_secret": self.manager.config.kick.client_secret,
                }

            session = requests.Session()
            response = session.post(token_url, data=data, timeout=30)
            response.raise_for_status()
            token_data = response.json()

            # Actualizar credenciales en el store
            new_creds = self.manager._build_credentials(
                platform, provider, token_data
            )
            self.manager.store.save(new_creds)

            return oauth_pb2.TokenResponse(
                platform=platform,
                access_token=new_creds.twitch.access_token if platform == "twitch" else new_creds.kick.access_token,
                refresh_token=new_creds.twitch.refresh_token if platform == "twitch" else new_creds.kick.refresh_token,
                token_type=new_creds.twitch.token_type if platform == "twitch" else new_creds.kick.token_type,
                expires_in=new_creds.twitch.expires_in or 0 if platform == "twitch" else new_creds.kick.expires_in or 0,
                scope=new_creds.twitch.scope if platform == "twitch" else new_creds.kick.scope,
                success=True,
                error="",
            )
        except Exception as exc:  # noqa: BLE001
            return oauth_pb2.TokenResponse(
                platform=platform,
                success=False,
                error=str(exc),
            )

    def GetCredentials(self, request, context):
        platform = request.platform.lower()
        provider = self.manager.provider(platform)
        if provider is None:
            return oauth_pb2.CredentialsResponse(
                platform=platform,
                success=False,
                error=f"Plataforma '{platform}' no configurada o no habilitada.",
            )

        store = self.manager.store
        creds = store.load()
        if platform == "twitch":
            pc = creds.twitch
            # expires_in restante calculado desde la expiración absoluta, no el valor original del flujo OAuth.
            expires_in = _remaining_seconds(pc.expires_at) if pc.expires_at else (pc.expires_in or 0)
            return oauth_pb2.CredentialsResponse(
                platform=platform,
                access_token=pc.access_token,
                refresh_token=pc.refresh_token,
                token_type=pc.token_type,
                expires_in=expires_in,
                scope=pc.scope,
                bot_user_id=creds.twitch_bot_user_id,
                broadcaster_ids=creds.twitch_broadcaster_ids,
                success=True,
                error="",
            )
        elif platform == "kick":
            pc = creds.kick
            expires_in = _remaining_seconds(pc.expires_at) if pc.expires_at else (pc.expires_in or 0)
            return oauth_pb2.CredentialsResponse(
                platform=platform,
                access_token=pc.access_token,
                refresh_token=pc.refresh_token,
                token_type=pc.token_type,
                expires_in=expires_in,
                scope=pc.scope,
                bot_user_id="",
                broadcaster_ids=creds.kick_broadcaster_ids,
                success=True,
                error="",
            )
        else:
            return oauth_pb2.CredentialsResponse(
                platform=platform,
                success=False,
                error=f"Plataforma '{platform}' no soportada.",
            )

    def RevokeToken(self, request, context):
        platform = request.platform.lower()
        provider = self.manager.provider(platform)
        if provider is None:
            return oauth_pb2.RevokeResponse(
                success=False,
                error=f"Plataforma '{platform}' no configurada o no habilitada.",
            )

        try:
            import requests

            if platform == "twitch":
                revoke_url = "https://id.twitch.tv/oauth2/revoke"
                headers = {}
                params = {
                    "token": request.token,
                    "client_id": self.manager.config.twitch.client_id,
                }
            else:
                revoke_url = "https://id.kick.com/oauth2/revoke"
                headers = {}
                params = {
                    "token": request.token,
                    "client_id": self.manager.config.kick.client_id,
                }

            session = requests.Session()
            response = session.post(
                revoke_url, params=params, headers=headers, timeout=30
            )
            response.raise_for_status()

            return oauth_pb2.RevokeResponse(success=True, error="")
        except Exception as exc:  # noqa: BLE001
            return oauth_pb2.RevokeResponse(success=False, error=str(exc))


def serve(port: int = 50052, manager: OAuthManager | None = None) -> grpc.Server:
    """Inicia el servidor gRPC en el puerto dado."""
    if manager is None:
        config = load_config()
        manager = OAuthManager(config)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    oauth_pb2_grpc.add_OAuthServiceServicer_to_server(
        OAuthServiceServicer(manager), server
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    return server


if __name__ == "__main__":
    config = load_config()
    manager = OAuthManager(config)
    grpc_server = serve(port=50052, manager=manager)
    print(f"gRPC server listening on [::]:50052")
    grpc_server.wait_for_termination()
