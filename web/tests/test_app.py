from pathlib import Path

from app import create_app
from bitchat_web.mesh import MeshNode


def test_configure_and_send_without_peers(tmp_path: Path):
    node = MeshNode(tmp_path, start_transport=False)
    app = create_app(node)
    client = app.test_client()

    index = client.get("/")
    assert index.status_code == 200
    assert b"encrypted Bluetooth mesh" in index.data

    response = client.post("/api/settings", json={"nickname": "alice", "room_code": "a secure room code"})
    assert response.status_code == 200
    sent = client.post("/api/messages", json={"text": "hello mesh"})
    assert sent.status_code == 200
    assert sent.get_json()["message"]["verified"] is True


def test_short_room_code_is_rejected(tmp_path: Path):
    node = MeshNode(tmp_path, start_transport=False)
    app = create_app(node)
    response = app.test_client().post("/api/settings", json={"nickname": "alice", "room_code": "short"})
    assert response.status_code == 400
