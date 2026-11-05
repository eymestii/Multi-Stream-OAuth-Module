"""Capa 3 - Configuración.

Carga las variables de entorno desde un archivo .env (o del entorno del
sistema) y las expone como un objeto de configuración tipificado.

Los campos coinciden con los listados en docs/Arch/archlayouts.md, además de
los necesarios para el flujo OAuth (client secret, redirect URI, scopes).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - python-dotenv es opcional en runtime

    def load_dotenv(*args, **kwargs):  # type: ignore[no-redef]
        return False


@dataclass
class TwitchConfig:
    """Configuración previa de Twitch (solo lo que el usuario rellena en .env).

    Los tokens (access_token, refresh_token, etc.) son resultado del flujo
    OAuth y se gestionan en oauth_module.credentials, no aquí.
    """

    enabled: bool = False
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = "http://localhost:8765/callback/twitch"
    scopes: List[str] = field(default_factory=list)


@dataclass
class KickConfig:
    """Configuración previa de Kick (solo lo que el usuario rellena en .env).

    Los tokens (access_token, refresh_token, etc.) son resultado del flujo
    OAuth y se gestionan en oauth_module.credentials, no aquí.
    """

    enabled: bool = False
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = "http://localhost:8765/callback/kick"
    webhook_addr: str = "0.0.0.0:8080"
    webhook_path: str = "/kick/webhook"
    auto_subscribe: bool = False
    send_as: str = "bot"
    public_key_pem: str = ""
    verify_signatures: bool = True
    scopes: List[str] = field(default_factory=list)


@dataclass
class OAuthConfig:
    """Configuración completa del módulo OAuth."""

    twitch: TwitchConfig = field(default_factory=TwitchConfig)
    kick: KickConfig = field(default_factory=KickConfig)
    local_host: str = "127.0.0.1"
    local_port: int = 8765

    @property
    def redirect_base(self) -> str:
        return f"http://{self.local_host}:{self.local_port}"


def _env_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def load_config(env_file: Optional[str] = None) -> OAuthConfig:
    """Carga la configuración desde un archivo .env y/o el entorno.

    Si se pasa ``env_file`` se cargan esas variables primero; las variables
    ya definidas en el entorno del sistema tienen prioridad.
    """
    if env_file:
        load_dotenv(env_file, override=False)
    else:
        # Carga .env del directorio de trabajo si existe, sin sobrescribir el
        # entorno ya definido.
        load_dotenv(override=False)

    twitch = TwitchConfig(
        enabled=_env_bool(os.getenv("TWITCH_ENABLED"), False),
        client_id=os.getenv("TWITCH_CLIENT_ID", "") or "",
        client_secret=os.getenv("TWITCH_CLIENT_SECRET", "") or "",
        redirect_uri=os.getenv("TWITCH_REDIRECT_URI", "") or "",
        scopes=_env_list(os.getenv("TWITCH_SCOPES")),
    )

    kick = KickConfig(
        enabled=_env_bool(os.getenv("KICK_ENABLED"), False),
        client_id=os.getenv("KICK_CLIENT_ID", "") or "",
        client_secret=os.getenv("KICK_CLIENT_SECRET", "") or "",
        redirect_uri=os.getenv("KICK_REDIRECT_URI", "") or "",
        webhook_addr=os.getenv("KICK_WEBHOOK_ADDR", "0.0.0.0:8080") or "0.0.0.0:8080",
        webhook_path=os.getenv("KICK_WEBHOOK_PATH", "/kick/webhook") or "/kick/webhook",
        auto_subscribe=_env_bool(os.getenv("KICK_AUTO_SUBSCRIBE"), False),
        send_as=os.getenv("KICK_SEND_AS", "bot") or "bot",
        public_key_pem=os.getenv("KICK_PUBLIC_KEY_PEM", "") or "",
        verify_signatures=_env_bool(os.getenv("KICK_VERIFY_SIGNATURES"), True),
        scopes=_env_list(os.getenv("KICK_SCOPES")),
    )

    return OAuthConfig(
        twitch=twitch,
        kick=kick,
        local_host=os.getenv("OAUTH_LOCAL_HOST", "127.0.0.1") or "127.0.0.1",
        local_port=int(os.getenv("OAUTH_LOCAL_PORT", "8765") or "8765"),
    )
