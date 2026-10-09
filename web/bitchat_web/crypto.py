from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


KDF_SALT = b"bitchat-web-room-key-v1"
KDF_ITERATIONS = 310_000


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def derive_room_key(room_code: str) -> bytes:
    if len(room_code) < 8:
        raise ValueError("Room code must contain at least 8 characters")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=KDF_SALT, iterations=KDF_ITERATIONS
    ).derive(room_code.encode("utf-8"))


def room_id(key: bytes) -> str:
    return hashlib.sha256(b"room-id:" + key).hexdigest()[:16]


@dataclass(frozen=True)
class Identity:
    private_key: rsa.RSAPrivateKey

    @property
    def public_der(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.public_der).hexdigest()[:16]

    @property
    def public_key_b64(self) -> str:
        return _b64(self.public_der)

    def sign(self, data: bytes) -> str:
        signature = self.private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return _b64(signature)

    def unwrap_key(self, wrapped_key_b64: str) -> bytes:
        wrapped = _unb64(wrapped_key_b64)
        try:
            key = self.private_key.decrypt(wrapped, padding.PKCS1v15())
            if len(key) == 32:
                return key
        except ValueError:
            pass
        # Current explicit cross-platform profile first, followed by the two
        # SHA-256 OAEP profiles emitted by earlier APK builds during migration.
        profiles = (
            (hashes.SHA1(), hashes.SHA1()),
            (hashes.SHA256(), hashes.SHA1()),
            (hashes.SHA256(), hashes.SHA256()),
        )
        for oaep_digest, mgf_digest in profiles:
            try:
                return self.private_key.decrypt(
                    wrapped,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=mgf_digest),
                        algorithm=oaep_digest,
                        label=None,
                    ),
                )
            except ValueError:
                continue
        raise ValueError("Decryption failed for supported RSA-OAEP parameters")


def load_or_create_identity(path: Path) -> Identity:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Identity file does not contain an RSA key")
        return Identity(key)

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    encoded = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    temp = path.with_suffix(".tmp")
    temp.write_bytes(encoded)
    try:
        os.chmod(temp, 0o600)
    except OSError:
        pass
    temp.replace(path)
    return Identity(key)


def encrypt_and_sign(
    payload: dict[str, Any], identity: Identity, key: bytes, aad: bytes
) -> tuple[str, str, str]:
    plain = canonical_json(payload)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plain, aad)
    return _b64(nonce), _b64(ciphertext), identity.sign(plain)


def decrypt_and_verify(
    nonce_b64: str,
    ciphertext_b64: str,
    signature_b64: str,
    public_key_b64: str,
    key: bytes,
    aad: bytes,
) -> dict[str, Any]:
    plain = AESGCM(key).decrypt(_unb64(nonce_b64), _unb64(ciphertext_b64), aad)
    public_key = serialization.load_der_public_key(_unb64(public_key_b64))
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Sender key is not RSA")
    try:
        public_key.verify(
            _unb64(signature_b64),
            plain,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("Invalid digital signature") from exc
    result = json.loads(plain)
    if not isinstance(result, dict):
        raise ValueError("Invalid message payload")
    return result


def verify_signature(data: bytes, signature_b64: str, public_key_b64: str) -> None:
    public_key = serialization.load_der_public_key(_unb64(public_key_b64))
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Sender key is not RSA")
    try:
        public_key.verify(
            _unb64(signature_b64),
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("Invalid digital signature") from exc


def wrap_key(key: bytes, recipient_public_key_b64: str) -> str:
    public_key = serialization.load_der_public_key(_unb64(recipient_public_key_b64))
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Recipient key is not RSA")
    wrapped = public_key.encrypt(key, padding.PKCS1v15())
    return _b64(wrapped)


def encrypt_private_and_sign(
    payload: dict[str, Any], identity: Identity, recipient_public_key_b64: str, aad: bytes
) -> tuple[str, str, str, str]:
    message_key = AESGCM.generate_key(bit_length=256)
    plain = canonical_json(payload)
    nonce = os.urandom(12)
    ciphertext = AESGCM(message_key).encrypt(nonce, plain, aad)
    return _b64(nonce), _b64(ciphertext), identity.sign(plain), wrap_key(message_key, recipient_public_key_b64)


def decrypt_private_and_verify(
    nonce_b64: str,
    ciphertext_b64: str,
    signature_b64: str,
    sender_public_key_b64: str,
    wrapped_key_b64: str,
    identity: Identity,
    aad: bytes,
) -> dict[str, Any]:
    message_key = identity.unwrap_key(wrapped_key_b64)
    plain = AESGCM(message_key).decrypt(_unb64(nonce_b64), _unb64(ciphertext_b64), aad)
    verify_signature(plain, signature_b64, sender_public_key_b64)
    result = json.loads(plain)
    if not isinstance(result, dict):
        raise ValueError("Invalid private message payload")
    return result


def fingerprint_public_key(public_key_b64: str) -> str:
    return hashlib.sha256(_unb64(public_key_b64)).hexdigest()[:16]
