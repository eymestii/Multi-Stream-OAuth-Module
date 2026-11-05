"""Capa 2 - Lógica OAuth: clase base para proveedores.

Define la interfaz común que implementan los proveedores de Twitch y Kick.
Los proveedores son desacoplados entre sí y de la interfaz de usuario.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

import requests

from ..credentials import PlatformCredentials


class OAuthProvider(ABC):
    """Interfaz de un proveedor de OAuth 2.0."""

    name: str
    authorize_url: str
    token_url: str

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: List[str],
        session: Optional[requests.Session] = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = list(scopes)
        self.session = session or requests.Session()

    @abstractmethod
    def get_authorization_url(self, state: str) -> str:
        """Construye la URL a la que se redirige al usuario para autorizar."""

    @abstractmethod
    def exchange_code(self, code: str, **kwargs) -> Dict[str, object]:
        """Intercambia el código de autorización por tokens."""

    def create_credentials(self, token_data: Dict[str, object]) -> PlatformCredentials:
        """Convierte la respuesta del endpoint de token en credenciales."""
        expires_in = token_data.get("expires_in")
        return PlatformCredentials(
            access_token=str(token_data.get("access_token", "") or ""),
            refresh_token=str(token_data.get("refresh_token", "") or ""),
            token_type=str(token_data.get("token_type", "bearer") or "bearer"),
            expires_in=int(expires_in) if expires_in is not None else None,
            scope=str(token_data.get("scope", "") or ""),
        )
