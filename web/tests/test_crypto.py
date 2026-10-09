from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from bitchat_web.crypto import decrypt_and_verify, derive_room_key, encrypt_and_sign, load_or_create_identity, room_id


def test_encrypt_sign_decrypt_verify(tmp_path: Path):
    identity = load_or_create_identity(tmp_path / "identity.pem")
    key = derive_room_key("correct horse battery staple")
    payload = {"id": "abc", "sender_id": identity.fingerprint, "nickname": "alice", "created_at": "now", "text": "hello"}
    aad = f"1|chat|abc|{room_id(key)}".encode()
    nonce, ciphertext, signature = encrypt_and_sign(payload, identity, key, aad)
    assert decrypt_and_verify(nonce, ciphertext, signature, identity.public_key_b64, key, aad) == payload


def test_wrong_room_key_cannot_decrypt(tmp_path: Path):
    identity = load_or_create_identity(tmp_path / "identity.pem")
    key = derive_room_key("room code alpha")
    wrong_key = derive_room_key("room code bravo")
    nonce, ciphertext, signature = encrypt_and_sign({"text": "secret"}, identity, key, b"header")
    with pytest.raises(InvalidTag):
        decrypt_and_verify(nonce, ciphertext, signature, identity.public_key_b64, wrong_key, b"header")
