"""Capa 2 - Lógica OAuth: proveedor de Kick (PKCE).

Kick usa OAuth 2.0 con PKCE (Proof Key for Code Exchange):
1. Se genera un code_verifier y su code_challenge (S256)
2. El usuario se redirige a https://id.kick.com/oauth/authorize
   incluyendo el code_challenge
3. Se intercambia el código por un access token enviando el code_verifier
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Dict, Optional
from urllib.parse import urlencode

from .base import OAuthProvider


class KickOAuthProvider(OAuthProvider):
    name = "kick"
    authorize_url = "https://id.kick.com/oauth/authorize"
    token_url = "https://id.kick.com/oauth/token"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._code_verifier: Optional[str] = None

    @staticmethod
    def generate_code_verifier() -> str:
        """Genera un code_verifier de entre 43 y 128 caracteres."""
        return secrets.token_urlsafe(96)[:128]

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Genera el code_challenge = base64url(sha256(code_verifier))."""
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def get_authorization_url(self, state: str) -> str:
        self._code_verifier = self.generate_code_verifier()
        challenge = self.generate_code_challenge(self._code_verifier)
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.authorize_url}?{urlencode(params)}"

    @property
    def code_verifier(self) -> Optional[str]:
        return self._code_verifier

    def exchange_code(self, code: str, **kwargs) -> Dict[str, object]:
        if not self._code_verifier:
            raise RuntimeError(
                "code_verifier no disponible: llama a get_authorization_url primero"
            )
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
            "code_verifier": self._code_verifier,
        }
        response = self.session.post(self.token_url, data=data, timeout=30)
        response.raise_for_status()
        return response.json()
