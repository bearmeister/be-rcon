# Author:   Bushy <contact@bushy.dev>
# Version:  v2.12.5
# Modified: 2026-05-14
#
# test_be_rcon.py: tests for be_rcon.

import socket
import struct
import zlib
from unittest.mock import MagicMock, patch
import pytest
from be_rcon import _crc32, _build, _parse, RConClient, main


class _StopListen(Exception):
    """Sentinel raised from a listen() callback to terminate the loop."""


def pkt(ptype: int, payload: bytes) -> bytes:
    """Build a valid BE packet (reuses production _build)."""
    return _build(ptype, payload)


# ---------------------------------------------------------------------------
# Packet helpers
# ---------------------------------------------------------------------------

class TestCrc32:
    def test_known_value(self):
        data = b"\xff\x00hello"
        assert _crc32(data) == zlib.crc32(data) & 0xFFFFFFFF

    def test_empty(self):
        assert _crc32(b"") == zlib.crc32(b"") & 0xFFFFFFFF

    def test_always_unsigned(self):
        for data in (b"test", b"\xff" * 100, b""):
            assert 0 <= _crc32(data) <= 0xFFFFFFFF

    def test_different_data_different_crc(self):
        assert _crc32(b"aaa") != _crc32(b"bbb")


class TestBuild:
    def test_starts_with_be(self):
        assert _build(0x00, b"pass").startswith(b"BE")

    def test_ff_marker_at_offset_6(self):
        assert _build(0x01, b"x")[6] == 0xFF

    def test_type_byte_at_offset_7(self):
        assert _build(0x01, b"x")[7] == 0x01
        assert _build(0x02, b"x")[7] == 0x02

    def test_payload_appended(self):
        pkt_bytes = _build(0x01, b"players")
        assert pkt_bytes[8:] == b"players"

    def test_crc_covers_body(self):
        pkt_bytes = _build(0x01, b"cmd")
        body = pkt_bytes[6:]
        crc_in_packet = struct.unpack("<I", pkt_bytes[2:6])[0]
        assert zlib.crc32(body) & 0xFFFFFFFF == crc_in_packet

    def test_roundtrip_via_parse(self):
        for ptype, payload in [(0x00, b"\x01"), (0x01, b"players"), (0x02, b"\x00")]:
            pt, pl = _parse(_build(ptype, payload))
            assert pt == ptype
            assert pl == payload


class TestParse:
    def test_valid_login_response(self):
        ptype, payload = _parse(pkt(0x00, b"\x01"))
        assert ptype == 0x00
        assert payload == b"\x01"

    def test_valid_command_response(self):
        ptype, payload = _parse(pkt(0x01, b"\x00data"))
        assert ptype == 0x01
        assert payload == b"\x00data"

    def test_empty_payload(self):
        ptype, payload = _parse(pkt(0x02, b""))
        assert ptype == 0x02
        assert payload == b""

    def test_bad_header_raises(self):
        with pytest.raises(ValueError, match="bad header"):
            _parse(b"XX" + b"\x00" * 10)

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            _parse(b"BE\x00\x00")

    def test_seven_bytes_raises_value_error_not_index_error(self):
        # 7-byte input is one short of the 8-byte minimum (BE + CRC + 0xFF + type).
        # Regression guard: previously raised IndexError on body[1] indexing
        # because the length check was < 7 instead of < 8.
        body = b"\xFF"
        crc = struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
        with pytest.raises(ValueError, match="bad header"):
            _parse(b"BE" + crc + body)

    def test_missing_ff_marker_raises(self):
        body = b"\x00\x01hello"  # 0x00 instead of 0xFF
        crc = struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
        with pytest.raises(ValueError, match="0xFF"):
            _parse(b"BE" + crc + body)

    def test_crc_mismatch_raises(self):
        bad = bytearray(_build(0x01, b"data"))
        bad[-1] ^= 0xFF
        with pytest.raises(ValueError, match="CRC"):
            _parse(bytes(bad))


# ---------------------------------------------------------------------------
# RConClient — helpers
# ---------------------------------------------------------------------------

def _mock_sock(recv_responses: list) -> MagicMock:
    sock = MagicMock()
    sock.recv.side_effect = recv_responses
    return sock


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

class TestLogin:
    @patch("be_rcon.socket.socket")
    def test_login_success(self, MockSocket):
        MockSocket.return_value = _mock_sock([pkt(0x00, b"\x01")])
        RConClient("127.0.0.1", 2305, "pass").connect()

    @patch("be_rcon.socket.socket")
    def test_socket_closed_on_login_failure(self, MockSocket):
        # connect() must release the OS socket if _login raises; otherwise
        # callers using bare connect() (not the context manager) leak FDs.
        sock = _mock_sock([pkt(0x00, b"\x00")])  # wrong-password reply
        MockSocket.return_value = sock
        rc = RConClient("127.0.0.1", 2305, "wrongpass")
        with pytest.raises(ConnectionError):
            rc.connect()
        sock.close.assert_called()
        assert rc._sock is None

    @patch("be_rcon.socket.socket")
    def test_login_wrong_password(self, MockSocket):
        MockSocket.return_value = _mock_sock([pkt(0x00, b"\x00")])
        with pytest.raises(ConnectionError, match="password"):
            RConClient("127.0.0.1", 2305, "wrongpass").connect()

    @patch("be_rcon.socket.socket")
    def test_login_unexpected_type_raises(self, MockSocket):
        MockSocket.return_value = _mock_sock([pkt(0x01, b"\x01")])
        with pytest.raises(ConnectionError, match="unexpected"):
            RConClient("127.0.0.1", 2305, "pass").connect()

    @patch("be_rcon.socket.socket")
    def test_login_empty_payload_raises(self, MockSocket):
        MockSocket.return_value = _mock_sock([pkt(0x00, b"")])
        with pytest.raises(ConnectionError):
            RConClient("127.0.0.1", 2305, "pass").connect()


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

class TestContextManager:
    @patch("be_rcon.socket.socket")
    def test_enter_returns_client(self, MockSocket):
        MockSocket.return_value = _mock_sock([pkt(0x00, b"\x01")])
        with RConClient("127.0.0.1", 2305, "pass") as rc:
            assert rc._sock is not None

    @patch("be_rcon.socket.socket")
    def test_exit_closes_socket(self, MockSocket):
        sock = _mock_sock([pkt(0x00, b"\x01")])
        MockSocket.return_value = sock
        with RConClient("127.0.0.1", 2305, "pass"):
            pass
        sock.close.assert_called()

    @patch("be_rcon.socket.socket")
    def test_sock_none_after_close(self, MockSocket):
        MockSocket.return_value = _mock_sock([pkt(0x00, b"\x01")])
        rc = RConClient("127.0.0.1", 2305, "pass")
        rc.connect()
        rc.close()
        assert rc._sock is None

    @patch("be_rcon.socket.socket")
    def test_double_close_is_safe(self, MockSocket):
        MockSocket.return_value = _mock_sock([pkt(0x00, b"\x01")])
        rc = RConClient("127.0.0.1", 2305, "pass")
        rc.connect()
        rc.close()
        rc.close()  # must not raise

    def test_send_command_without_connect_raises_runtime_error(self):
        # Replaces the bare `assert self._sock` — assert is stripped under
        # `python -O`, so distribution code must raise a real exception.
        rc = RConClient("127.0.0.1", 2305, "pass")
        with pytest.raises(RuntimeError, match="not connected"):
            rc.send_command("status")

    def test_listen_without_connect_raises_runtime_error(self):
        rc = RConClient("127.0.0.1", 2305, "pass")
        with pytest.raises(RuntimeError, match="not connected"):
            rc.listen(lambda _m: None)


# ---------------------------------------------------------------------------
# send_command
# ---------------------------------------------------------------------------

class TestSendCommand:
    def _client(self, MockSocket, extra_responses: list) -> RConClient:
        MockSocket.return_value = _mock_sock([pkt(0x00, b"\x01")] + extra_responses)
        rc = RConClient("127.0.0.1", 2305, "pass", timeout=0.1)
        rc.connect()
        return rc

    @patch("be_rcon.socket.socket")
    def test_single_part_response(self, MockSocket):
        rc = self._client(MockSocket, [pkt(0x01, bytes([0]) + b"player list")])
        assert rc.send_command("players") == "player list"

    @patch("be_rcon.socket.socket")
    def test_timeout_returns_empty(self, MockSocket):
        MockSocket.return_value = _mock_sock([pkt(0x00, b"\x01"), socket.timeout()])
        rc = RConClient("127.0.0.1", 2305, "pass", timeout=0.1)
        rc.connect()
        assert rc.send_command("players") == ""

    @patch("be_rcon.socket.socket")
    def test_sequence_increments(self, MockSocket):
        rc = self._client(MockSocket, [
            pkt(0x01, bytes([0]) + b"r0"),
            pkt(0x01, bytes([1]) + b"r1"),
        ])
        assert rc.send_command("cmd1") == "r0"
        assert rc.send_command("cmd2") == "r1"

    @patch("be_rcon.socket.socket")
    def test_sequence_rolls_over_at_256(self, MockSocket):
        # Provide login + one command response in a single side_effect list
        MockSocket.return_value = _mock_sock([
            pkt(0x00, b"\x01"),                      # login ok
            pkt(0x01, bytes([255]) + b"r"),           # seq=255 response
        ])
        rc = RConClient("127.0.0.1", 2305, "pass", timeout=0.1)
        rc.connect()
        rc._seq = 255
        rc.send_command("x")
        assert rc._seq == 0

    @patch("be_rcon.socket.socket")
    def test_multipart_assembled_in_order(self, MockSocket):
        seq = 0
        rc = self._client(MockSocket, [
            pkt(0x01, bytes([seq, 0x00, 2, 0]) + b"hello "),
            pkt(0x01, bytes([seq, 0x00, 2, 1]) + b"world"),
        ])
        assert rc.send_command("players") == "hello world"

    @patch("be_rcon.socket.socket")
    def test_broadcast_acked_and_ignored(self, MockSocket):
        seq = 0
        rc = self._client(MockSocket, [
            pkt(0x02, bytes([7]) + b"server msg"),  # broadcast
            pkt(0x01, bytes([seq]) + b"result"),
        ])
        assert rc.send_command("status") == "result"

    @patch("be_rcon.socket.socket")
    def test_wrong_seq_skipped(self, MockSocket):
        rc = self._client(MockSocket, [
            pkt(0x01, bytes([99]) + b"wrong seq"),  # seq 99, not 0
            socket.timeout(),
        ])
        assert rc.send_command("x") == ""

    @patch("be_rcon.socket.socket")
    def test_corrupt_packet_skipped(self, MockSocket):
        bad = b"GARBAGE NOT A PACKET"
        rc = self._client(MockSocket, [bad, socket.timeout()])
        assert rc.send_command("x") == ""


# ---------------------------------------------------------------------------
# listen
# ---------------------------------------------------------------------------

class TestListen:
    @patch("be_rcon.socket.socket")
    def test_listen_acks_broadcast(self, MockSocket):
        sock = _mock_sock([pkt(0x00, b"\x01"), pkt(0x02, bytes([42]) + b"hello")])
        MockSocket.return_value = sock
        msgs: list[str] = []

        def cb(m: str) -> None:
            msgs.append(m)
            raise _StopListen()

        rc = RConClient("127.0.0.1", 2305, "pass")
        rc.connect()
        with pytest.raises(_StopListen):
            rc.listen(cb)

        assert msgs == ["hello"]
        sends = [c.args[0] for c in sock.send.call_args_list]
        acks = [s for s in sends if _parse(s) == (0x02, bytes([42]))]
        assert len(acks) == 1

    @patch("be_rcon.time.monotonic")
    @patch("be_rcon.socket.socket")
    def test_listen_sends_keepalive(self, MockSocket, mock_time):
        # last_ka = 0; iter1: 0-0 < 25, recv timeout; iter2: 30-0 >= 25,
        # send keepalive; iter3: recv OSError -> exit.
        mock_time.side_effect = [0, 0, 30, 30, 30, 60, 60]
        sock = _mock_sock([
            pkt(0x00, b"\x01"),
            socket.timeout(),
            OSError("eof"),
        ])
        MockSocket.return_value = sock

        rc = RConClient("127.0.0.1", 2305, "pass")
        rc.connect()
        rc.listen(lambda _m: None)

        sends = [c.args[0] for c in sock.send.call_args_list]
        keepalives = [s for s in sends if _parse(s)[0] == 0x01]
        assert len(keepalives) == 1
        # Keepalive payload is just the seq byte, no command text.
        _, ka_payload = _parse(keepalives[0])
        assert len(ka_payload) == 1

    @patch("be_rcon.time.monotonic")
    @patch("be_rcon.socket.socket")
    def test_listen_keepalive_send_failure_surfaces_via_callback(self, MockSocket, mock_time):
        # Keepalive send raising OSError used to break silently; now it must
        # emit "[socket error] ..." through the callback, matching recv's
        # OSError handling.
        mock_time.side_effect = [0, 0, 30, 30, 30, 60]
        sock = _mock_sock([pkt(0x00, b"\x01"), socket.timeout()])
        sock.send.side_effect = [None, OSError("send pipe broken")]
        MockSocket.return_value = sock
        msgs: list[str] = []

        rc = RConClient("127.0.0.1", 2305, "pass")
        rc.connect()
        rc.listen(msgs.append)  # returns cleanly

        assert len(msgs) == 1
        assert msgs[0].startswith("[socket error]")
        assert "send pipe broken" in msgs[0]

    @patch("be_rcon.socket.socket")
    def test_listen_socket_error_exits(self, MockSocket):
        sock = _mock_sock([pkt(0x00, b"\x01"), OSError("connection reset")])
        MockSocket.return_value = sock
        msgs: list[str] = []

        rc = RConClient("127.0.0.1", 2305, "pass")
        rc.connect()
        rc.listen(msgs.append)  # returns cleanly, no raise

        assert len(msgs) == 1
        assert msgs[0].startswith("[socket error]")
        assert "connection reset" in msgs[0]

    @patch("be_rcon.socket.socket")
    def test_listen_corrupt_packet_skipped(self, MockSocket):
        sock = _mock_sock([
            pkt(0x00, b"\x01"),
            b"GARBAGE NOT A PACKET",
            pkt(0x02, bytes([5]) + b"valid"),
        ])
        MockSocket.return_value = sock
        msgs: list[str] = []

        def cb(m: str) -> None:
            msgs.append(m)
            raise _StopListen()

        rc = RConClient("127.0.0.1", 2305, "pass")
        rc.connect()
        with pytest.raises(_StopListen):
            rc.listen(cb)

        assert msgs == ["valid"]


# ---------------------------------------------------------------------------
# main() — console-script entry point
# ---------------------------------------------------------------------------

class TestMain:
    def test_no_args_exits_with_usage(self):
        with pytest.raises(SystemExit) as exc:
            main([])
        assert "usage:" in str(exc.value)

    def test_unknown_mode_exits(self):
        with pytest.raises(SystemExit) as exc:
            main(["wat", "host", "2305", "pw"])
        assert "unknown mode" in str(exc.value)

    @patch("be_rcon.cli_cmd")
    def test_cmd_mode_dispatches_to_cli_cmd(self, mock_cli_cmd):
        main(["cmd", "host", "2305", "pw", "say", "hi"])
        mock_cli_cmd.assert_called_once_with(["host", "2305", "pw", "say", "hi"])

    @patch("be_rcon.cli_shell")
    def test_shell_mode_dispatches_to_cli_shell(self, mock_cli_shell):
        main(["shell", "host", "2305", "pw"])
        mock_cli_shell.assert_called_once_with(["host", "2305", "pw"])

    @patch("be_rcon.cli_cmd")
    @patch("be_rcon.sys")
    def test_argv_none_falls_back_to_sys_argv(self, mock_sys, mock_cli_cmd):
        # `main(None)` must use sys.argv[1:] — verifies console-script path
        # (no argv passed when invoked as `be-rcon ...` from a shell).
        mock_sys.argv = ["be-rcon", "cmd", "host", "2305", "pw", "ping"]
        main()
        mock_cli_cmd.assert_called_once_with(["host", "2305", "pw", "ping"])
