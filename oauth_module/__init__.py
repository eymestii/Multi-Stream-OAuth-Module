"""oauth_module

Módulo de autenticación OAuth para Twitch (Authorization Code) y Kick (PKCE).

Organizado en tres capas, tal como se describe en docs/Arch/archlayouts.md:

    Capa 1 - Interfaz:      oauth_module.ui  (Qt6, botones de login)
    Capa 2 - Lógica:        oauth_module.providers (OAuth de Twitch y Kick)
    Capa 3 - Exposición:    oauth_module.credentials (archivo de credenciales)
                            oauth_module.config    (variables de entorno)
"""

__version__ = "1.0.0"

from .config import OAuthConfig, load_config
from .credentials import OAuthCredentials, CredentialsStore

__all__ = [
    "__version__",
    "OAuthConfig",
    "load_config",
    "OAuthCredentials",
    "CredentialsStore",
]
