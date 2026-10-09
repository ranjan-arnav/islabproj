from __future__ import annotations

import platform
import re
import socket
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Callable

from .protocol import FrameDecoder, encode_frame


DEFAULT_CHANNEL = 12
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def bluetooth_supported() -> bool:
    return all(
        hasattr(socket, name)
        for name in ("AF_BLUETOOTH", "BTPROTO_RFCOMM")
    )


def paired_devices() -> list[dict[str, str]]:
    """Return paired/known device addresses where the OS exposes them."""
    system = platform.system()
    if system == "Windows":
        command = (
            "$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices';"
            "if(Test-Path $p){Get-ChildItem $p|ForEach-Object{$_.PSChildName}}"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            devices = []
            for raw in result.stdout.splitlines():
                value = raw.strip()
                if re.fullmatch(r"[0-9a-fA-F]{12}", value):
                    address = ":".join(value[i : i + 2] for i in range(0, 12, 2)).upper()
                    devices.append({"address": address, "name": "Paired Bluetooth device"})
            return devices
        except (OSError, subprocess.SubprocessError):
            return []
    if system == "Linux":
        try:
            result = subprocess.run(
                ["bluetoothctl", "devices", "Paired"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            devices = []
            for line in result.stdout.splitlines():
                match = re.match(r"Device\s+([0-9A-Fa-f:]{17})\s+(.+)", line)
                if match:
                    devices.append({"address": match.group(1).upper(), "name": match.group(2)})
            return devices
        except (OSError, subprocess.SubprocessError):
            return []
    return []


@dataclass
class Link:
    id: str
    sock: socket.socket
    address: str
    direction: str
    on_packet: Callable[[dict, str], None]
    on_close: Callable[[str], None]
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    alive: bool = True

    def start(self) -> None:
        threading.Thread(target=self._read_loop, name=f"bt-read-{self.id}", daemon=True).start()

    def send(self, packet: dict) -> None:
        frame = encode_frame(packet)
        with self.send_lock:
            self.sock.sendall(frame)

    def close(self) -> None:
        if not self.alive:
            return
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def _read_loop(self) -> None:
        decoder = FrameDecoder()
        try:
            while self.alive:
                data = self.sock.recv(8192)
                if not data:
                    break
                for packet in decoder.feed(data):
                    self.on_packet(packet, self.id)
        except (OSError, ValueError, UnicodeError):
            pass
        finally:
            self.close()
            self.on_close(self.id)


class BluetoothTransport:
    def __init__(
        self,
        on_packet: Callable[[dict, str], None],
        on_links_changed: Callable[[], None],
        channel: int = DEFAULT_CHANNEL,
    ) -> None:
        self.on_packet = on_packet
        self.on_links_changed = on_links_changed
        self.channel = channel
        self.links: dict[str, Link] = {}
        self.lock = threading.RLock()
        self.server: socket.socket | None = None
        self.error: str | None = None
        self.local_address: str | None = None

    def start(self) -> None:
        if not bluetooth_supported():
            self.error = "Python Bluetooth sockets are unavailable on this operating system"
            return
        try:
            server = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            any_address = "00:00:00:00:00:00" if platform.system() == "Windows" else ""
            server.bind((any_address, self.channel))
            server.listen(7)
            self.server = server
            self.local_address = server.getsockname()[0]
            threading.Thread(target=self._accept_loop, name="bt-accept", daemon=True).start()
        except OSError as exc:
            self.error = f"Bluetooth listener failed: {exc}"

    def connect(self, address: str, channel: int | None = None) -> Link:
        if not MAC_RE.fullmatch(address):
            raise ValueError("Enter a Bluetooth MAC address like AA:BB:CC:DD:EE:FF")
        if not bluetooth_supported():
            raise RuntimeError("Bluetooth RFCOMM is not supported by this Python build")
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        sock.settimeout(15)
        try:
            sock.connect((address, channel or self.channel))
            sock.settimeout(None)
            return self._add_link(sock, address.upper(), "outbound")
        except Exception:
            sock.close()
            raise

    def broadcast(self, packet: dict, exclude: str | None = None) -> int:
        sent = 0
        with self.lock:
            links = list(self.links.values())
        for link in links:
            if link.id == exclude or not link.alive:
                continue
            try:
                link.send(packet)
                sent += 1
            except OSError:
                link.close()
        return sent

    def disconnect(self, link_id: str) -> None:
        with self.lock:
            link = self.links.get(link_id)
        if link:
            link.close()
            self._remove_link(link_id)

    def snapshot(self) -> list[dict[str, str]]:
        with self.lock:
            return [
                {"id": link.id, "address": link.address, "direction": link.direction}
                for link in self.links.values()
                if link.alive
            ]

    def close(self) -> None:
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
        with self.lock:
            links = list(self.links.values())
        for link in links:
            link.close()

    def _accept_loop(self) -> None:
        assert self.server is not None
        while True:
            try:
                sock, address = self.server.accept()
                remote = address[0] if isinstance(address, tuple) else str(address)
                self._add_link(sock, remote, "inbound")
            except OSError:
                return

    def _add_link(self, sock: socket.socket, address: str, direction: str) -> Link:
        import uuid

        link = Link(uuid.uuid4().hex[:10], sock, address, direction, self.on_packet, self._remove_link)
        with self.lock:
            self.links[link.id] = link
        link.start()
        self.on_links_changed()
        return link

    def _remove_link(self, link_id: str) -> None:
        with self.lock:
            self.links.pop(link_id, None)
        self.on_links_changed()
