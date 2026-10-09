from __future__ import annotations

import copy
import threading
import time
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto import (
    canonical_json,
    decrypt_and_verify,
    decrypt_private_and_verify,
    derive_room_key,
    encrypt_and_sign,
    encrypt_private_and_sign,
    fingerprint_public_key,
    load_or_create_identity,
    room_id,
    verify_signature,
)
from .protocol import packet_aad
from .transport import BluetoothTransport, paired_devices


MAX_TTL = 7
MAX_MESSAGE_CHARS = 2000
SEEN_LIMIT = 2000
ANNOUNCE_INTERVAL_SECONDS = 12


class MeshNode:
    def __init__(self, data_dir: Path, channel: int = 12, start_transport: bool = True) -> None:
        self.data_dir = data_dir
        self.identity = load_or_create_identity(data_dir / "identity.pem")
        self.nickname = "anonymous"
        self._room_key: bytes | None = None
        self._room_id: str | None = None
        self._messages: deque[dict[str, Any]] = deque(maxlen=500)
        self._events: deque[dict[str, Any]] = deque(maxlen=100)
        self._participants: dict[str, dict[str, Any]] = {}
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._sequence = 0
        self._lock = threading.RLock()
        self.transport = BluetoothTransport(self.receive_packet, self._links_changed, channel)
        if start_transport:
            self.transport.start()
            threading.Thread(target=self._announce_loop, name="mesh-announcer", daemon=True).start()

    def configure(self, nickname: str, room_code: str) -> None:
        nickname = nickname.strip()
        if not nickname or len(nickname) > 32:
            raise ValueError("Nickname must be between 1 and 32 characters")
        key = derive_room_key(room_code)
        with self._lock:
            self.nickname = nickname
            self._room_key = key
            self._room_id = room_id(key)
            self._messages.clear()
            self._participants.clear()
            self._seen.clear()
        self._event("security", "Room key derived locally; it was not transmitted")
        self.announce()

    def connect(self, address: str, channel: int | None = None) -> dict[str, str]:
        link = self.transport.connect(address.strip(), channel)
        self._event("peer", f"Connected to {link.address}")
        self.announce()
        return {"id": link.id, "address": link.address, "direction": link.direction}

    def announce(self) -> dict[str, Any] | None:
        with self._lock:
            if self._room_id is None:
                return None
            payload = {
                "id": uuid.uuid4().hex,
                "room_id": self._room_id,
                "sender_id": self.identity.fingerprint,
                "nickname": self.nickname,
                "public_key": self.identity.public_key_b64,
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        packet: dict[str, Any] = {"v": 1, "type": "announce", "ttl": MAX_TTL, **payload}
        packet["signature"] = self.identity.sign(canonical_json(payload))
        self._remember(packet["id"])
        self.transport.broadcast(packet)
        return packet

    def send_message(self, text: str, recipient_id: str | None = None) -> dict[str, Any]:
        text = text.strip()
        if not text:
            raise ValueError("Message cannot be empty")
        if len(text) > MAX_MESSAGE_CHARS:
            raise ValueError(f"Message cannot exceed {MAX_MESSAGE_CHARS} characters")
        key, current_room = self._configured_room()
        message_id = uuid.uuid4().hex
        payload: dict[str, Any] = {
            "id": message_id,
            "sender_id": self.identity.fingerprint,
            "nickname": self.nickname,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "text": text,
            "private": bool(recipient_id),
        }

        if recipient_id:
            with self._lock:
                recipient = self._participants.get(recipient_id)
            if recipient is None:
                raise ValueError("Recipient is not currently discoverable on the mesh")
            payload["recipient_id"] = recipient_id
            payload["recipient_nickname"] = recipient["nickname"]
            packet: dict[str, Any] = {
                "v": 1,
                "type": "private",
                "id": message_id,
                "room_id": current_room,
                "ttl": MAX_TTL,
                "sender_id": self.identity.fingerprint,
                "recipient_id": recipient_id,
                "public_key": self.identity.public_key_b64,
            }
            nonce, ciphertext, signature, wrapped_key = encrypt_private_and_sign(
                payload, self.identity, recipient["public_key"], packet_aad(packet)
            )
            packet.update(
                {"nonce": nonce, "ciphertext": ciphertext, "signature": signature, "wrapped_key": wrapped_key}
            )
        else:
            packet = {
                "v": 1,
                "type": "chat",
                "id": message_id,
                "room_id": current_room,
                "ttl": MAX_TTL,
                "sender_id": self.identity.fingerprint,
                "public_key": self.identity.public_key_b64,
            }
            nonce, ciphertext, signature = encrypt_and_sign(payload, self.identity, key, packet_aad(packet))
            packet.update({"nonce": nonce, "ciphertext": ciphertext, "signature": signature})

        self._remember(message_id)
        rendered = self._append_message(payload, verified=True, local=True, hops=0)
        self.transport.broadcast(packet)
        return rendered

    def receive_packet(self, packet: dict[str, Any], ingress: str) -> None:
        try:
            packet_type = packet.get("type")
            if packet_type == "announce":
                self._receive_announce(packet, ingress)
            elif packet_type == "private":
                self._receive_private(packet, ingress)
            elif packet_type == "chat":
                self._receive_chat(packet, ingress)
            else:
                raise ValueError("Unsupported packet type")
        except Exception as exc:
            self._event("blocked", f"Rejected packet: {exc}")

    def _receive_announce(self, packet: dict[str, Any], ingress: str) -> None:
        required = {
            "v", "type", "id", "room_id", "ttl", "sender_id", "public_key",
            "nickname", "created_at", "signature",
        }
        self._validate_fields(packet, required, "announce")
        if self._already_seen(packet["id"]):
            return
        _key, current_room = self._configured_room()
        if packet["room_id"] != current_room:
            return
        if fingerprint_public_key(packet["public_key"]) != packet["sender_id"]:
            raise ValueError("Announced fingerprint does not match public key")
        if not 1 <= len(packet["nickname"]) <= 32:
            raise ValueError("Invalid announced nickname")
        signed = {
            key: packet[key]
            for key in ("id", "room_id", "sender_id", "nickname", "public_key", "created_at")
        }
        verify_signature(canonical_json(signed), packet["signature"], packet["public_key"])
        self._remember(packet["id"])
        if packet["sender_id"] != self.identity.fingerprint:
            with self._lock:
                self._participants[packet["sender_id"]] = {
                    "id": packet["sender_id"],
                    "nickname": packet["nickname"],
                    "public_key": packet["public_key"],
                    "last_seen": time.monotonic(),
                    "hops": MAX_TTL - packet["ttl"] + 1,
                }
                self._sequence += 1
        self._relay(packet, ingress)

    def _receive_chat(self, packet: dict[str, Any], ingress: str) -> None:
        required = {
            "v", "type", "id", "room_id", "ttl", "sender_id", "public_key",
            "nonce", "ciphertext", "signature",
        }
        self._validate_fields(packet, required, "chat")
        if self._already_seen(packet["id"]):
            return
        key, current_room = self._configured_room()
        if packet["room_id"] != current_room:
            return
        payload = decrypt_and_verify(
            packet["nonce"], packet["ciphertext"], packet["signature"],
            packet["public_key"], key, packet_aad(packet),
        )
        self._validate_sender(packet, payload)
        self._remember(packet["id"])
        self._append_message(payload, verified=True, local=False, hops=MAX_TTL - packet["ttl"] + 1)
        self._relay(packet, ingress)

    def _receive_private(self, packet: dict[str, Any], ingress: str) -> None:
        required = {
            "v", "type", "id", "room_id", "ttl", "sender_id", "recipient_id",
            "public_key", "wrapped_key", "nonce", "ciphertext", "signature",
        }
        self._validate_fields(packet, required, "private")
        if self._already_seen(packet["id"]):
            return
        _key, current_room = self._configured_room()
        if packet["room_id"] != current_room:
            return
        self._remember(packet["id"])

        if packet["recipient_id"] != self.identity.fingerprint:
            # An intermediate node forwards only opaque bytes and records no chat/event entry.
            self._relay(packet, ingress)
            return

        payload = decrypt_private_and_verify(
            packet["nonce"], packet["ciphertext"], packet["signature"], packet["public_key"],
            packet["wrapped_key"], self.identity, packet_aad(packet),
        )
        self._validate_sender(packet, payload)
        if payload.get("recipient_id") != self.identity.fingerprint:
            raise ValueError("Private message recipient does not match envelope")
        self._append_message(payload, verified=True, local=False, hops=MAX_TTL - packet["ttl"] + 1)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "nickname": self.nickname,
                "configured": self._room_key is not None,
                "room_id": self._room_id,
                "fingerprint": self.identity.fingerprint,
                "bluetooth_supported": self.transport.error is None,
                "bluetooth_error": self.transport.error,
                "local_address": self.transport.local_address,
                "channel": self.transport.channel,
                "peers": self.transport.snapshot(),
                "participants": self._participant_snapshot(),
                "messages": list(self._messages),
                "events": list(self._events),
                "sequence": self._sequence,
                "paired_devices": paired_devices(),
            }

    def messages_after(self, sequence: int) -> dict[str, Any]:
        with self._lock:
            return {
                "messages": [m for m in self._messages if m["sequence"] > sequence],
                "events": [e for e in self._events if e["sequence"] > sequence],
                "sequence": self._sequence,
                "peers": self.transport.snapshot(),
                "participants": self._participant_snapshot(),
            }

    def panic(self) -> None:
        with self._lock:
            self._room_key = None
            self._room_id = None
            self._messages.clear()
            self._participants.clear()
            self._seen.clear()
        self._event("security", "Session key and in-memory messages were wiped")

    def _configured_room(self) -> tuple[bytes, str]:
        with self._lock:
            if self._room_key is None or self._room_id is None:
                raise ValueError("Join a room before sending or receiving messages")
            return self._room_key, self._room_id

    def _validate_fields(self, packet: dict[str, Any], required: set[str], packet_type: str) -> None:
        if set(packet) != required:
            raise ValueError("Malformed packet fields")
        if packet["v"] != 1 or packet["type"] != packet_type:
            raise ValueError("Unsupported packet version or type")
        if not isinstance(packet["ttl"], int) or not 1 <= packet["ttl"] <= MAX_TTL:
            raise ValueError("Invalid packet TTL")
        for field in required - {"v", "ttl"}:
            if not isinstance(packet[field], str):
                raise ValueError(f"Invalid {field}")

    def _validate_sender(self, packet: dict[str, Any], payload: dict[str, Any]) -> None:
        if payload.get("id") != packet["id"] or payload.get("sender_id") != packet["sender_id"]:
            raise ValueError("Signed content does not match its envelope")
        if fingerprint_public_key(packet["public_key"]) != packet["sender_id"]:
            raise ValueError("Sender fingerprint does not match public key")

    def _relay(self, packet: dict[str, Any], ingress: str) -> None:
        if packet["ttl"] > 1:
            relayed = copy.copy(packet)
            relayed["ttl"] -= 1
            self.transport.broadcast(relayed, exclude=ingress)

    def _already_seen(self, message_id: str) -> bool:
        with self._lock:
            return message_id in self._seen

    def _remember(self, message_id: str) -> None:
        with self._lock:
            self._seen[message_id] = time.monotonic()
            self._seen.move_to_end(message_id)
            while len(self._seen) > SEEN_LIMIT:
                self._seen.popitem(last=False)

    def _append_message(self, payload: dict[str, Any], verified: bool, local: bool, hops: int) -> dict[str, Any]:
        text = payload.get("text")
        nickname = payload.get("nickname")
        if not isinstance(text, str) or len(text) > MAX_MESSAGE_CHARS:
            raise ValueError("Invalid message text")
        if not isinstance(nickname, str) or not 1 <= len(nickname) <= 32:
            raise ValueError("Invalid nickname")
        with self._lock:
            self._sequence += 1
            item = {**payload, "verified": verified, "local": local, "hops": hops, "sequence": self._sequence}
            self._messages.append(item)
            return item

    def _participant_snapshot(self) -> list[dict[str, Any]]:
        participants = []
        now = time.monotonic()
        for participant in self._participants.values():
            if now - participant["last_seen"] <= ANNOUNCE_INTERVAL_SECONDS * 3:
                participants.append({key: participant[key] for key in ("id", "nickname", "hops")})
        return sorted(participants, key=lambda item: (item["nickname"].lower(), item["id"]))

    def _event(self, kind: str, text: str) -> None:
        with self._lock:
            self._sequence += 1
            self._events.append(
                {
                    "kind": kind,
                    "text": text,
                    "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "sequence": self._sequence,
                }
            )

    def _links_changed(self) -> None:
        self._event("peer", f"{len(self.transport.snapshot())} Bluetooth peer(s) connected")
        self.announce()

    def _announce_loop(self) -> None:
        while True:
            time.sleep(ANNOUNCE_INTERVAL_SECONDS)
            try:
                self.announce()
            except Exception:
                pass
