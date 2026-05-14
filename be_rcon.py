# Author:   Bushy <contact@bushy.dev>
# Version:  v2.12.5
# Modified: 2026-05-14
#
# be_rcon.py: unofficial BattlEye RCon (UDP) client. cmd / shell / listen modes.
# Upstream: https://github.com/bearmeister/be-rcon
# Protocol: https://www.battleye.com/downloads/BERConProtocol.txt
#
# Not affiliated with or endorsed by BattlEye Innovations e.K.
# "BattlEye" is a trademark of BattlEye Innovations e.K.

"""
BattlEye RCon protocol reference:
  https://www.battleye.com/downloads/BERConProtocol.txt

Packet layout:
  'BE'(2) | CRC32-LE(4) | 0xFF | type(1) | payload
  CRC32 covers everything from 0xFF onward.

Types:
  0x00  login     client→server: password; server→client: 0x00=fail 0x01=ok
  0x01  command   client→server: seq(1)+cmd; server→client: seq(1)+data
                  multi-part:    seq(1)+0x00+total(1)+idx(1)+data
  0x02  message   server→client: seq(1)+text; client ACKs with seq(1)
"""

from __future__ import annotations

import readline  # noqa: F401: enables line editing in shell mode
import socket
import struct
import sys
import time
import zlib
from typing import Callable, Optional

__all__ = ["RConClient", "cli_cmd", "cli_shell", "main"]


# ---------------------------------------------------------------------------
# Packet helpers
# ---------------------------------------------------------------------------

def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFF_FFFF


def _build(ptype: int, payload: bytes) -> bytes:
    body = bytes([0xFF, ptype]) + payload
    return b"BE" + struct.pack("<I", _crc32(body)) + body


def _parse(data: bytes) -> tuple[int, bytes]:
    """Return (type, payload). Raises ValueError on bad packet."""
    # Min valid packet: BE(2) + CRC(4) + 0xFF(1) + type(1) = 8 bytes.
    if len(data) < 8 or data[:2] != b"BE":
        raise ValueError("bad header")
    expected = struct.unpack("<I", data[2:6])[0]
    body = data[6:]
    if body[0] != 0xFF:
        raise ValueError("missing 0xFF marker")
    if _crc32(body) != expected:
        raise ValueError("CRC mismatch")
    return body[1], body[2:]


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class RConClient:
    """BattlEye RCon client.

    Not thread-safe: `_seq` is a plain read-modify-write counter shared by
    `send_command` and `listen`'s keepalive. Do not share a single client
    across threads: instantiate one per thread.
    """

    def __init__(self, host: str, port: int, password: str, timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._seq = 0

    # -- lifecycle -----------------------------------------------------------

    def connect(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self.timeout)
        self._sock.connect((self.host, self.port))
        try:
            self._login()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "RConClient":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _require_sock(self) -> socket.socket:
        """Return the live socket or raise: replaces `assert` for `-O` safety."""
        if self._sock is None:
            raise RuntimeError(
                "RConClient not connected: call connect() or use as context manager"
            )
        return self._sock

    # -- login ---------------------------------------------------------------

    def _login(self) -> None:
        sock = self._require_sock()
        # latin-1 round-trips every byte losslessly; BattlEye predates Unicode
        # and DayZ servers commonly emit cp1252 / latin-1 player names.
        sock.send(_build(0x00, self.password.encode("latin-1", errors="replace")))
        data = sock.recv(4096)
        ptype, payload = _parse(data)
        if ptype != 0x00 or not payload:
            raise ConnectionError("unexpected login response")
        if payload[0] != 0x01:
            raise ConnectionError("login failed: wrong password?")

    # -- commands ------------------------------------------------------------

    def send_command(self, command: str) -> str:
        """Send a command, collect (possibly multi-part) response, return text.

        Passing `""` sends a 0x01 packet with an empty payload, which
        BattlEye treats as a keepalive ping (same idiom `listen()` uses).
        """
        sock = self._require_sock()
        seq = self._seq
        self._seq = (self._seq + 1) % 256

        sock.send(_build(0x01, bytes([seq]) + command.encode("latin-1", errors="replace")))

        parts: dict[int, bytes] = {}
        total: Optional[int] = None
        deadline = time.monotonic() + self.timeout

        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            sock.settimeout(remaining)
            try:
                raw = sock.recv(65535)
            except socket.timeout:
                break

            try:
                ptype, payload = _parse(raw)
            except ValueError:
                continue

            if ptype == 0x02:
                # server broadcast during command: ACK and discard
                if payload:
                    self._ack(payload[0])
                continue

            if ptype != 0x01 or not payload or payload[0] != seq:
                continue

            # single-part: payload = seq + data (no 0x00 second byte)
            if len(payload) < 2 or payload[1] != 0x00:
                return payload[1:].decode("latin-1")

            # multi-part: payload = seq + 0x00 + total + idx + data
            if len(payload) < 4:
                break
            total = payload[2]
            idx = payload[3]
            parts[idx] = payload[4:]
            if len(parts) == total:
                break

        if total is not None and parts:
            return b"".join(parts[i] for i in sorted(parts)).decode("latin-1")
        return ""

    def _ack(self, seq: int) -> None:
        sock = self._require_sock()
        try:
            sock.send(_build(0x02, bytes([seq])))
        except OSError:
            pass  # ACK is best-effort; server retransmits broadcasts on missed ACK

    # -- listen (server messages) -------------------------------------------

    def listen(self, callback: Callable[[str], None]) -> None:
        """Block and call callback(msg) for each server broadcast.

        Sends keepalives every 25s so the server doesn't drop the connection.
        """
        sock = self._require_sock()
        sock.settimeout(1.0)
        last_ka = time.monotonic()

        while True:
            if time.monotonic() - last_ka >= 25:
                seq = self._seq
                self._seq = (self._seq + 1) % 256
                try:
                    sock.send(_build(0x01, bytes([seq])))
                except OSError as e:
                    callback(f"[socket error] {e}")
                    break
                last_ka = time.monotonic()

            try:
                raw = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError as e:
                callback(f"[socket error] {e}")
                break

            try:
                ptype, payload = _parse(raw)
            except ValueError:
                continue

            if ptype == 0x02 and payload:
                self._ack(payload[0])
                msg = payload[1:].decode("latin-1")
                callback(msg)


# ---------------------------------------------------------------------------
# CLI entry points
# ---------------------------------------------------------------------------

def _parse_port(raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        sys.exit(f"port must be an integer (got {raw!r})")


def cli_cmd(args: list[str]) -> None:
    """Send a single command and print the response."""
    if len(args) < 4:
        sys.exit("usage: be_rcon.py cmd <host> <port> <pass> <command...>")
    host = args[0]
    port = _parse_port(args[1])
    pw = args[2]
    command = " ".join(args[3:])
    with RConClient(host, port, pw) as rc:
        result = rc.send_command(command)
    if result:
        print(result)


def cli_shell(args: list[str]) -> None:
    """Interactive RCon shell."""
    if len(args) < 3:
        sys.exit("usage: be_rcon.py shell <host> <port> <pass>")
    host, port, pw = args[0], _parse_port(args[1]), args[2]
    with RConClient(host, port, pw) as rc:
        print(f"Connected to {host}:{port}. Type 'exit' or Ctrl-D to quit.")
        while True:
            try:
                line = input("rcon> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            if line.lower() in ("exit", "quit"):
                break
            result = rc.send_command(line)
            if result:
                print(result)


def main(argv: Optional[list[str]] = None) -> None:
    """Console-script entry point.

    Wire into pyproject as:
        [project.scripts]
        be-rcon = "be_rcon:main"

    `argv` defaults to `sys.argv[1:]`; tests pass a list explicitly.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        sys.exit("usage: be-rcon cmd|shell <host> <port> <pass> [command...]")
    mode, *rest = args
    if mode == "cmd":
        cli_cmd(rest)
    elif mode == "shell":
        cli_shell(rest)
    else:
        sys.exit(f"unknown mode: {mode}")


if __name__ == "__main__":
    main()
