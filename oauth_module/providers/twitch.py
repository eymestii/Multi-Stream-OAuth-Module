"""Capa 2 - Lógica OAuth: proveedor de Twitch (Authorization Code Flow).

Flujo oficial de Twitch:
1. El usuario se redirige a https://id.twitch.tv/oauth2/authorize
2. Twitch devuelve un código de autorización al redirect URI
3. Se intercambia el código por un access token en
   https://id.twitch.tv/oauth2/token
"""

from __future__ import annotations

from typing import Dict

from urllib.parse import urlencode

from .base import OAuthProvider


class TwitchOAuthProvider(OAuthProvider):
    name = "twitch"
    authorize_url = "https://id.twitch.tv/oauth2/authorize"
    token_url = "https://id.twitch.tv/oauth2/token"

    def get_authorization_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            "force_verify": "true",
        }
        return f"{self.authorize_url}?{urlencode(params)}"

    def exchange_code(self, code: str, **kwargs) -> Dict[str, object]:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        response = self.session.post(self.token_url, data=data, timeout=30)
        response.raise_for_status()
        return response.json()
