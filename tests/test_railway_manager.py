"""Tests for railway_manager ($PORT multiplexer + sing-box supervisor)."""
import base64
import contextlib
import json
import os
import socket
import stat
import tempfile
import unittest
from unittest import mock

from railway_manager import RailwayManager, build_config_from_env, classify_first_bytes, default_fetch
from vpngate_to_singbox import build_singbox_config, ovpn_to_endpoint


@contextlib.contextmanager
def _fake_singbox():
    """Stub out process launch + config check (no sing-box binary in unit tests)."""
    with mock.patch("railway_manager.subprocess.Popen"), \
         mock.patch.object(RailwayManager, "_check_config", return_value=True):
        yield


def get_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _read_json(path: str):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


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

    def _request(self, method: str, path: str, body: bytes | None = None,
                 token: str | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            headers = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            if token is not None:
                headers += f"Authorization: Bearer {token}\r\n"
            if body is not None:
                headers += f"Content-Length: {len(body)}\r\n"
            sock.sendall(headers.encode() + b"\r\n" + (body or b""))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def _get(self, path: str) -> bytes:
        return self._request("GET", path)

    def test_healthz_returns_ok_when_healthy(self) -> None:
        self.manager.status["endpoints"] = [
            {"tag": "vpngate-0", "server": "203.0.113.11", "server_port": 443}]
        response = self._get("/healthz")

        self.assertIn(b"200 OK", response)
        self.assertTrue(response.rstrip().endswith(b"ok"))

    def test_healthz_returns_503_without_endpoints(self) -> None:
        response = self._get("/healthz")

        self.assertIn(b"503", response)

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
                        config_path=f"/tmp/railway-test-{id(self)}.json",
                        nodes_path=f"/tmp/railway-test-{id(self)}-nodes.json",
                        state_path=f"/tmp/railway-test-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_refresh_once_updates_status_and_restarts_singbox(self) -> None:
        manager = self._manager(start_singbox=True)
        try:
            with mock.patch("railway_manager.subprocess.Popen") as popen, \
                 mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                 mock.patch("railway_manager.probe_tcp_latency", return_value=100):
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
        manager = self._manager(retry_delays=(0, 0))
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


class AuthTests(unittest.TestCase):
    TOKEN = "test-admin-token-0123456789abcdef"

    def setUp(self) -> None:
        self.manager = RailwayManager(
            port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
        )
        self.port = self.manager.start()

    def tearDown(self) -> None:
        self.manager.stop()

    def _request(self, method: str, path: str, body: bytes | None = None,
                 token: str | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            headers = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            if token is not None:
                headers += f"Authorization: Bearer {token}\r\n"
            if body is not None:
                headers += f"Content-Length: {len(body)}\r\n"
            sock.sendall(headers.encode() + b"\r\n" + (body or b""))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_status_without_token_is_401(self) -> None:
        self.assertIn(b"401", self._request("GET", "/api/status"))

    def test_status_with_wrong_token_is_401(self) -> None:
        self.assertIn(b"401", self._request("GET", "/api/status", token="nope"))

    def test_status_with_token_is_200(self) -> None:
        self.assertIn(b"200 OK", self._request("GET", "/api/status", token=self.TOKEN))

    def test_healthz_needs_no_token(self) -> None:
        self.manager.status["endpoints"] = [{"tag": "vpngate-0"}]
        self.assertIn(b"200 OK", self._request("GET", "/healthz"))

    def test_refresh_requires_post_and_token(self) -> None:
        self.assertIn(b"401", self._request("POST", "/api/refresh"))
        self.assertIn(b"405", self._request("GET", "/api/refresh", token=self.TOKEN))

    def test_ui_page_mentions_token_auth(self) -> None:
        response = self._request("GET", "/ui", token=self.TOKEN)

        self.assertIn(b"200 OK", response)
        self.assertIn(b"Authorization", response)


class EnvValidationTests(unittest.TestCase):
    def _env(self, **overrides):
        env = {"PORT": "8080", "PROXY_USER": "u", "PROXY_PASS": "0123456789abcdef"}
        env.update(overrides)
        return env

    def test_weak_proxy_pass_exits_nonzero(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            build_config_from_env(self._env(PROXY_PASS="short"))

        self.assertNotEqual(0, ctx.exception.code)

    def test_default_proxy_pass_exits_nonzero(self) -> None:
        with self.assertRaises(SystemExit):
            build_config_from_env(self._env(PROXY_PASS="p"))

    def test_non_https_snapshot_url_exits_nonzero(self) -> None:
        with self.assertRaises(SystemExit):
            build_config_from_env(self._env(SNAPSHOT_URL="http://example.com/x.csv"))

    def test_valid_env_builds_config(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(8080, config["port"])
        self.assertEqual("0123456789abcdef", config["password"])

    def test_default_fetch_rejects_plain_http(self) -> None:
        with self.assertRaises(ValueError):
            default_fetch("http://example.com/x.csv", timeout=1)


class SwitchTests(unittest.TestCase):
    TOKEN = "test-admin-token-0123456789abcdef"

    def _csv_two_countries(self) -> str:
        def row(host, ip, speed, country_long, country_short):
            config = base64.b64encode(
                TCP_OVPN.replace("203.0.113.1", ip).encode()).decode()
            return f"{host},{ip},100,20,{speed},{country_long},{country_short},1,{config}"

        header = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
        return "\n".join([
            header,
            row("vpn-jp", "203.0.113.11", 5000, "Japan", "JP"),
            row("vpn-us", "203.0.113.12", 1000, "United States", "US"),
        ]) + "\n"

    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
                        start_singbox=True, auto_refresh=False, fetch_on_start=False,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json",
                        fetcher=lambda url, timeout: self._csv_two_countries())
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _request(self, port: int, method: str, path: str,
                 body: bytes | None = None, token: str | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            headers = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            if token is not None:
                headers += f"Authorization: Bearer {token}\r\n"
            if body is not None:
                headers += f"Content-Length: {len(body)}\r\n"
            sock.sendall(headers.encode() + b"\r\n" + (body or b""))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_switch_by_country_picks_lowest_latency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            port = manager.start()
            try:
                with _fake_singbox():
                    with mock.patch(
                            "railway_manager.probe_tcp_latency",
                            side_effect=lambda h, p, timeout=5: (
                                900 if h == "203.0.113.11" else 100)):
                        self.assertTrue(manager.refresh_once())
                    body = json.dumps({"country": "US"}).encode()
                    response = self._request(port, "POST", "/api/switch", body, self.TOKEN)

                self.assertIn(b"200 OK", response)
                self.assertEqual("vpngate-0", manager.preferred_tag)
                written = _read_json(f"{tmpdir}/singbox.json")
                self.assertEqual("vpngate-0", written["route"]["final"])
            finally:
                manager.stop()

    def test_switch_unknown_country_is_400(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            port = manager.start()
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())
                body = json.dumps({"country": "XX"}).encode()
                response = self._request(port, "POST", "/api/switch", body, self.TOKEN)

                self.assertIn(b"400", response)
                self.assertIsNone(manager.preferred_tag)
            finally:
                manager.stop()

    def test_switch_by_tag_and_back_to_auto(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())

                    ok, tag = manager.switch(tag="vpngate-0")
                    self.assertTrue(ok)
                    self.assertEqual("vpngate-0", tag)
                    written = _read_json(f"{tmpdir}/singbox.json")
                    self.assertEqual("vpngate-0", written["route"]["final"])

                    ok, tag = manager.switch(tag="auto")
                    self.assertTrue(ok)
                    self.assertIsNone(manager.preferred_tag)
                    written = _read_json(f"{tmpdir}/singbox.json")
                    self.assertEqual("auto", written["route"]["final"])
            finally:
                manager.stop()

    def test_status_lists_countries_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())

                self.assertIn({"code": "JP", "name": "Japan"},
                              manager.status_snapshot()["countries"])
                self.assertIn({"code": "US", "name": "United States"},
                              manager.status_snapshot()["countries"])
                self.assertTrue(any(e["event"] == "refresh-ok"
                                    for e in manager.status_snapshot()["refresh_history"]))
            finally:
                manager.stop()

    def test_nodes_and_state_persist_and_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())
                    manager.switch(tag="vpngate-1")
            finally:
                manager.stop()

            reloaded = self._manager(tmpdir)
            nodes, preferred = reloaded.load_persisted()
            try:
                self.assertEqual(2, len(nodes))
                self.assertEqual("vpngate-1", preferred)
            finally:
                reloaded.stop()

    def test_config_file_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())

                if os.name != "nt":
                    mode = stat.S_IMODE(os.stat(f"{tmpdir}/singbox.json").st_mode)
                    self.assertEqual(0o600, mode)
            finally:
                manager.stop()


class PinnedHealthTests(unittest.TestCase):
    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(),
                        start_singbox=True, auto_refresh=False, fetch_on_start=False,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json",
                        fetcher=lambda url, timeout: self._csv())
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _csv(self) -> str:
        config = base64.b64encode(TCP_OVPN.encode()).decode()
        header = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
        return f"{header}\nvpn-jp,203.0.113.11,100,20,5000,Japan,JP,1,{config}\n"

    def test_three_consecutive_failures_unpins_to_auto(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())
                    manager.switch(tag="vpngate-0")

                    failing = lambda host, port, timeout=5: 0
                    self.assertEqual("pinned", manager.check_pinned_health(probe_fn=failing))
                    self.assertEqual("pinned", manager.check_pinned_health(probe_fn=failing))
                    self.assertEqual("unpinned", manager.check_pinned_health(probe_fn=failing))

                self.assertIsNone(manager.preferred_tag)
                written = _read_json(f"{tmpdir}/singbox.json")
                self.assertEqual("auto", written["route"]["final"])
            finally:
                manager.stop()

    def test_healthy_pinned_node_stays_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())
                    manager.switch(tag="vpngate-0")

                    healthy = lambda host, port, timeout=5: 120
                    self.assertEqual("pinned", manager.check_pinned_health(probe_fn=healthy))

                self.assertEqual("vpngate-0", manager.preferred_tag)
            finally:
                manager.stop()


if __name__ == "__main__":
    unittest.main()
