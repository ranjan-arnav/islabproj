from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


MAX_FRAME_BYTES = 64 * 1024


def packet_aad(packet: dict[str, Any]) -> bytes:
    fields = [str(packet["v"]), packet["type"], packet["id"], packet["room_id"]]
    if packet["type"] == "private":
        fields.extend([packet["sender_id"], packet["recipient_id"]])
    return "|".join(fields).encode("ascii")


def encode_frame(packet: dict[str, Any]) -> bytes:
    data = json.dumps(packet, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(data) > MAX_FRAME_BYTES:
        raise ValueError("Packet exceeds the 64 KiB limit")
    return data + b"\n"


@dataclass
class FrameDecoder:
    buffer: bytearray = field(default_factory=bytearray)

    def feed(self, data: bytes) -> list[dict[str, Any]]:
        self.buffer.extend(data)
        if len(self.buffer) > MAX_FRAME_BYTES * 2:
            raise ValueError("Incoming frame buffer is too large")
        frames: list[dict[str, Any]] = []
        while True:
            try:
                index = self.buffer.index(10)
            except ValueError:
                break
            raw = bytes(self.buffer[:index])
            del self.buffer[: index + 1]
            if not raw:
                continue
            if len(raw) > MAX_FRAME_BYTES:
                raise ValueError("Incoming packet exceeds the 64 KiB limit")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("Packet must be a JSON object")
            frames.append(value)
        return frames
