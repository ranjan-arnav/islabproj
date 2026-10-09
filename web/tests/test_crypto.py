import base64
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

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


@pytest.mark.parametrize(
    ("oaep_digest", "mgf_digest"),
    [
        (hashes.SHA1(), hashes.SHA1()),
        (hashes.SHA256(), hashes.SHA1()),
        (hashes.SHA256(), hashes.SHA256()),
    ],
)
def test_identity_unwraps_android_oaep_migration_variants(tmp_path: Path, oaep_digest, mgf_digest):
    identity = load_or_create_identity(tmp_path / "identity.pem")
    public_key = serialization.load_der_public_key(base64.urlsafe_b64decode(identity.public_key_b64))
    message_key = os.urandom(32)
    wrapped = public_key.encrypt(
        message_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=mgf_digest),
            algorithm=oaep_digest,
            label=None,
        ),
    )
    assert identity.unwrap_key(base64.urlsafe_b64encode(wrapped).decode("ascii")) == message_key


def test_identity_unwraps_cross_platform_pkcs1_message_key(tmp_path: Path):
    identity = load_or_create_identity(tmp_path / "identity.pem")
    public_key = serialization.load_der_public_key(base64.urlsafe_b64decode(identity.public_key_b64))
    message_key = os.urandom(32)
    wrapped = public_key.encrypt(message_key, padding.PKCS1v15())
    assert identity.unwrap_key(base64.urlsafe_b64encode(wrapped).decode("ascii")) == message_key
