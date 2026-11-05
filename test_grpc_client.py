"""Cliente de prueba para el servidor gRPC de OAuth."""

from __future__ import annotations

import grpc

from oauth_module.proto import oauth_pb2, oauth_pb2_grpc


def test_grpc_server(channel_address: str = "localhost:50052") -> None:
    """Prueba todas las llamadas del servicio gRPC."""
    channel = grpc.insecure_channel(channel_address)
    stub = oauth_pb2_grpc.OAuthServiceStub(channel)

    print("=" * 60)
    print("Prueba 1: GetToken - Twitch")
    print("=" * 60)
    response = stub.GetToken(oauth_pb2.TokenRequest(platform="twitch"))
    print(f"  platform: {response.platform}")
    print(f"  access_token: {response.access_token[:20]}...")
    print(f"  refresh_token: {response.refresh_token[:20]}...")
    print(f"  token_type: {response.token_type}")
    print(f"  expires_in: {response.expires_in}")
    print(f"  scope: {response.scope}")
    print(f"  success: {response.success}")
    print(f"  error: {response.error}")
    assert response.success, f"GetToken twitch falló: {response.error}"
    assert response.access_token, "access_token vacío"
    assert "moderator:read:chat_messages" in response.scope, "Falta scope moderator:read:chat_messages"

    print()
    print("=" * 60)
    print("Prueba 2: GetToken - Kick")
    print("=" * 60)
    response = stub.GetToken(oauth_pb2.TokenRequest(platform="kick"))
    print(f"  platform: {response.platform}")
    print(f"  access_token: {response.access_token[:20]}...")
    print(f"  refresh_token: {response.refresh_token[:20]}...")
    print(f"  token_type: {response.token_type}")
    print(f"  expires_in: {response.expires_in}")
    print(f"  scope: {response.scope}")
    print(f"  success: {response.success}")
    print(f"  error: {response.error}")
    assert response.success, f"GetToken kick falló: {response.error}"
    assert response.access_token, "access_token vacío"

    print()
    print("=" * 60)
    print("Prueba 3: GetCredentials - Twitch")
    print("=" * 60)
    response = stub.GetCredentials(oauth_pb2.CredentialsRequest(platform="twitch"))
    print(f"  platform: {response.platform}")
    print(f"  access_token: {response.access_token[:20]}...")
    print(f"  bot_user_id: {response.bot_user_id}")
    print(f"  broadcaster_ids: {response.broadcaster_ids}")
    print(f"  scope: {response.scope}")
    print(f"  success: {response.success}")
    print(f"  error: {response.error}")
    assert response.success, f"GetCredentials twitch falló: {response.error}"
    assert response.bot_user_id == "1153760357", f"bot_user_id inesperado: {response.bot_user_id}"
    assert response.broadcaster_ids == "1153760357", f"broadcaster_ids inesperado: {response.broadcaster_ids}"

    print()
    print("=" * 60)
    print("Prueba 4: GetCredentials - Kick")
    print("=" * 60)
    response = stub.GetCredentials(oauth_pb2.CredentialsRequest(platform="kick"))
    print(f"  platform: {response.platform}")
    print(f"  access_token: {response.access_token[:20]}...")
    print(f"  broadcaster_ids: {response.broadcaster_ids}")
    print(f"  scope: {response.scope}")
    print(f"  success: {response.success}")
    print(f"  error: {response.error}")
    assert response.success, f"GetCredentials kick falló: {response.error}"
    assert response.broadcaster_ids == "70239105", f"broadcaster_ids inesperado: {response.broadcaster_ids}"

    print()
    print("=" * 60)
    print("Prueba 5: GetToken - plataforma inválida")
    print("=" * 60)
    response = stub.GetToken(oauth_pb2.TokenRequest(platform="invalida"))
    print(f"  success: {response.success}")
    print(f"  error: {response.error}")
    assert not response.success, "Debería fallar para plataforma inválida"

    print()
    print("=" * 60)
    print("TODAS LAS PRUEBAS PASARON")
    print("=" * 60)
    channel.close()


if __name__ == "__main__":
    test_grpc_server()
