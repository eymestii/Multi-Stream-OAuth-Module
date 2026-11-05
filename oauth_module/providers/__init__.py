"""Paquete de proveedores OAuth (capa 2)."""

from .base import OAuthProvider
from .kick import KickOAuthProvider
from .twitch import TwitchOAuthProvider

__all__ = ["OAuthProvider", "KickOAuthProvider", "TwitchOAuthProvider"]
