"""Tests for railway_manager ($PORT multiplexer + sing-box supervisor)."""
import base64
import json
import socket
import unittest
from unittest import mock

from railway_manager import RailwayManager, classify_first_bytes
from vpngate_to_singbox import build_singbox_config, ovpn_to_endpoint


def get_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


TCP_OVPN = """\
client
dev tun
proto tcp-client
remote 203.0.113.1 443 tcp
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
Q0E=
-----END CERTIFICATE-----
</ca>
"""


def _snapshot_csv(*ips: str) -> str:
    header = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
    rows = []
    for i, ip in enumerate(ips):
        config = base64.b64encode(TCP_OVPN.replace("203.0.113.1", ip).encode()).decode()
        rows.append(f"vpn-{i},{ip},100,20,{1000 + i},Japan,JP,1,{config}")
    return header + "\n" + "\n".join(rows) + "\n"


class ClassifyTests(unittest.TestCase):
    def test_socks5_greeting(self) -> None:
        self.assertEqual("socks5", classify_first_bytes(b"\x05\x01\x00"))

    def test_http_connect(self) -> None:
        self.assertEqual("http-connect", classify_first_bytes(b"CONNECT example.com:443 HTTP/1.1\r\n"))

    def test_http_get(self) -> None:
        self.assertEqual("http", classify_first_bytes(b"GET /healthz HTTP/1.1\r\n"))

    def test_empty_is_unknown(self) -> None:
        self.assertEqual("unknown", classify_first_bytes(b""))

    def test_tls_is_unknown(self) -> None:
        self.assertEqual("unknown", classify_first_bytes(b"\x16\x03\x01\x00\x80"))


class MixedUsersTests(unittest.TestCase):
    def test_users_injected_into_mixed_inbound(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config(
            [endpoint], mixed_listen="127.0.0.1", mixed_port=40000,
            mixed_users=[("u", "p")],
        )

        users = cfg["inbounds"][0]["users"]
        self.assertEqual([{"username": "u", "password": "p"}], users)


class MultiplexerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
        )
        self.port = self.manager.start()

    def tearDown(self) -> None:
        self.manager.stop()

    def _get(self, path: str) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_healthz_returns_ok(self) -> None:
        response = self._get("/healthz")

        self.assertIn(b"200 OK", response)
        self.assertTrue(response.rstrip().endswith(b"ok"))

    def test_status_returns_json(self) -> None:
        response = self._get("/api/status")
        body = response.split(b"\r\n\r\n", 1)[1]

        status = json.loads(body.decode())
        self.assertIn("endpoints", status)
        self.assertIn("last_refresh", status)

    def test_ui_returns_html(self) -> None:
        response = self._get("/ui")

        self.assertIn(b"200 OK", response)
        self.assertIn(b"text/html", response)
        self.assertIn(b"/api/status", response)

    def test_unknown_path_returns_404(self) -> None:
        response = self._get("/nope")

        self.assertIn(b"404", response)

    def test_socks5_dispatch_closes_when_backend_down(self) -> None:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            sock.sendall(b"\x05\x01\x00")
            sock.settimeout(5)
            data = sock.recv(16)

        self.assertEqual(b"", data)


class RefreshTests(unittest.TestCase):
    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        config_path=f"/tmp/railway-test-{id(self)}.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_refresh_once_updates_status_and_restarts_singbox(self) -> None:
        manager = self._manager(start_singbox=True)
        try:
            with mock.patch("railway_manager.subprocess.Popen") as popen:
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11", "203.0.113.12"))
        finally:
            manager.stop()

        self.assertTrue(ok)
        self.assertEqual(["vpngate-0", "vpngate-1"],
                         [ep["tag"] for ep in manager.status["endpoints"]])
        self.assertIsNotNone(manager.status["last_refresh"])
        self.assertIsNone(manager.status["last_error"])
        popen.assert_called_once()

    def test_refresh_failure_keeps_old_endpoints(self) -> None:
        manager = self._manager()
        manager.status["endpoints"] = [{"tag": "old"}]
        try:
            def boom(url, timeout):
                raise TimeoutError("network down")

            ok = manager.refresh_once(fetcher=boom)
        finally:
            manager.stop()

        self.assertFalse(ok)
        self.assertEqual([{"tag": "old"}], manager.status["endpoints"])
        self.assertIn("network down", manager.status["last_error"])


if __name__ == "__main__":
    unittest.main()
