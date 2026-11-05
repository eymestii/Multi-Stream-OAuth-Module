## Capas del proyecto

- Capa 1

Interfaz Qt6 para UI con dos botones, login con twitch y login con kick.

- Capa 2

Capa logica, proceso oficial para oauth Twitch y PKCE para kick por aparte, desacoplados. Con todos los scopes de ambas plataformas.

- Capa 3

Capa de exposicion. Un archivo con las credenciales que regresa twitch y kick deben llenarse los campos que pide el siguiente modulo de la aplicación.

# ---------------- Twitch (EventSub WebSocket)
TWITCH_ENABLED=true
TWITCH_CLIENT_ID=
TWITCH_ACCESS_TOKEN=
TWITCH_BOT_USER_ID=
TWITCH_BROADCASTER_IDS=

# ---------------- Kick (webhooks)
KICK_ENABLED=true
KICK_WEBHOOK_ADDR=0.0.0.0:8080
KICK_WEBHOOK_PATH=/kick/webhook
KICK_ACCESS_TOKEN=
KICK_BROADCASTER_IDS=
KICK_AUTO_SUBSCRIBE=false
KICK_SEND_AS=bot
KICK_PUBLIC_KEY_PEM=
KICK_VERIFY_SIGNATURES=true

