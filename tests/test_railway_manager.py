"""Tests for railway_manager ($PORT multiplexer + sing-box supervisor)."""
import base64
import contextlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from railway_manager import (UI_HTML, RailwayManager, build_config_from_env,
                               classify_first_bytes, default_fetch)
from vpngate_to_singbox import (build_singbox_config, nodes_to_endpoints,
                                ovpn_to_endpoint, snapshot_to_nodes)


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


class DisguiseRootTests(unittest.TestCase):
    MARKER = "<!-- disguise-page-marker -->"

    def _manager(self, disguise_path: str) -> RailwayManager:
        return RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            disguise_path=disguise_path,
        )

    def _get_root(self, manager: RailwayManager, port: int) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_root_serves_disguise_file(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False,
                                         encoding="utf-8") as handle:
            handle.write(f"<html><body>{self.MARKER}</body></html>")
            path = handle.name
        manager = self._manager(path)
        port = manager.start()
        try:
            response = self._get_root(manager, port)
        finally:
            manager.stop()
            os.unlink(path)

        self.assertIn(b"200 OK", response)
        self.assertIn(self.MARKER.encode(), response)
        self.assertNotIn(b"/api/status", response)

    def test_root_falls_back_to_console_without_disguise_file(self) -> None:
        manager = self._manager("/nonexistent/disguise.html")
        port = manager.start()
        try:
            response = self._get_root(manager, port)
        finally:
            manager.stop()

        self.assertIn(b"200 OK", response)
        self.assertIn(b"/api/status", response)

    def test_ui_still_serves_console_when_disguise_set(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False,
                                         encoding="utf-8") as handle:
            handle.write(f"<html><body>{self.MARKER}</body></html>")
            path = handle.name
        manager = self._manager(path)
        port = manager.start()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            with sock:
                sock.sendall(b"GET /ui HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        finally:
            manager.stop()
            os.unlink(path)

        self.assertIn(b"200 OK", response)
        self.assertIn(b"/api/status", response)


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

    def test_refresh_passes_real_topk_and_reports_real_latency(self) -> None:
        dialed: list[str] = []
        real_by_server = {"203.0.113.12": 50}

        def fake_dial(node):
            dialed.append(node["server"])
            return real_by_server.get(node["server"])

        manager = self._manager(real_topk=2, dial_fn=fake_dial)
        try:
            with mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                 mock.patch("railway_manager.probe_tcp_latency", return_value=100):
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv(
                        "203.0.113.11", "203.0.113.12", "203.0.113.13"))
        finally:
            manager.stop()

        self.assertTrue(ok)
        servers = [ep["server"] for ep in manager.status["endpoints"]]
        reals = [ep["real_latency_ms"] for ep in manager.status["endpoints"]]
        # handshake ties break by speed desc, so .13/.12 are dialed;
        # measured .12 sorts first and tags follow final order
        self.assertEqual({"203.0.113.13", "203.0.113.12"}, set(dialed))
        self.assertEqual(["203.0.113.12", "203.0.113.13", "203.0.113.11"], servers)
        self.assertEqual([50, None, None], reals)

    def test_first_seen_pruned_to_current_nodes(self) -> None:
        manager = self._manager()
        manager._first_seen = {
            "203.0.113.11:443": "2020-01-01T00:00:00Z",  # still present: keep stamp
            "198.51.100.99:443": "2020-01-01T00:00:00Z",  # vanished: prune
        }
        try:
            with mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                 mock.patch("railway_manager.probe_tcp_latency", return_value=100):
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11", "203.0.113.12"))
        finally:
            manager.stop()

        self.assertTrue(ok)
        self.assertEqual("2020-01-01T00:00:00Z",
                         manager._first_seen.get("203.0.113.11:443"))
        self.assertNotIn("198.51.100.99:443", manager._first_seen)
        self.assertIn("203.0.113.12:443", manager._first_seen)

    def test_refresh_full_scans_every_candidate(self) -> None:
        manager = self._manager()
        try:
            with mock.patch("railway_manager.snapshot_to_nodes",
                            return_value=[]) as snapshot_mock:
                manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11"))
        finally:
            manager.stop()

        _, kwargs = snapshot_mock.call_args
        self.assertEqual(0, kwargs.get("probe_pool"))

    def test_refresh_once_accepts_probe_pool_override(self) -> None:
        manager = self._manager()
        try:
            with mock.patch("railway_manager.snapshot_to_nodes",
                            return_value=[]) as snapshot_mock:
                manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11"),
                    probe_pool=30)
        finally:
            manager.stop()

        _, kwargs = snapshot_mock.call_args
        self.assertEqual(30, kwargs.get("probe_pool"))

    def test_initial_refresh_uses_bounded_pool_for_fast_cold_start(self) -> None:
        from railway_manager import INITIAL_PROBE_POOL
        manager = self._manager()
        try:
            with mock.patch.object(RailwayManager, "_boot_from_last_good",
                                   return_value=False), \
                 mock.patch.object(RailwayManager, "refresh_once",
                                   return_value=True) as refresh_mock:
                manager._initial_refresh()
        finally:
            manager.stop()

        _, kwargs = refresh_mock.call_args
        self.assertEqual(INITIAL_PROBE_POOL, kwargs.get("probe_pool"))


class FullProbeTests(unittest.TestCase):
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"/tmp/railway-probe-{id(self)}.json",
                        nodes_path=f"/tmp/railway-probe-{id(self)}-nodes.json",
                        state_path=f"/tmp/railway-probe-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path, token=True):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   + (f"Authorization: Bearer {self.TOKEN}\r\n" if token else ""))
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": None,
                           "speed": 1000} for ip in ips]

    def test_full_probe_rejects_missing_token(self) -> None:
        manager = self._manager()
        try:
            status_line, _ = self._post(manager, "/api/full_probe", token=False)
        finally:
            manager.stop()

        self.assertIn("401", status_line)

    def test_full_probe_accepts_and_runs_in_background(self) -> None:
        manager = self._manager(dial_fn=lambda node: 50)
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            status_line, body = self._post(manager, "/api/full_probe", token=True)
            accepted_state = manager.status["full_probe"]["state"]
            manager._full_probe_thread.join(timeout=30)
            final_state = manager.status["full_probe"]["state"]
        finally:
            manager.stop()

        self.assertIn("202", status_line)
        self.assertTrue(json.loads(body.decode())["accepted"])
        self.assertEqual("running", accepted_state)
        self.assertEqual("done", final_state)
        self.assertEqual(2, manager.status["full_probe"]["done"])
        self.assertEqual(2, manager.status["full_probe"]["total"])

    def test_full_probe_fills_real_latency_for_every_node(self) -> None:
        manager = self._manager(dial_fn=lambda node: 77)
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            self._post(manager, "/api/full_probe", token=True)
            manager._full_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertEqual([77, 77],
                         [n["real_latency_ms"] for n in manager._nodes])
        self.assertEqual([77, 77],
                         [ep["real_latency_ms"]
                          for ep in manager.status["endpoints"]])

    def test_default_dial_fn_measures_real(self) -> None:
        manager = self._manager()
        try:
            dial_fn = manager.dial_fn
        finally:
            manager.stop()

        self.assertIsNotNone(dial_fn)


class SingleProbeTests(unittest.TestCase):
    """POST /api/probe dials one untried node; success auto-marks it usable."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"/tmp/railway-single-{id(self)}.json",
                        nodes_path=f"/tmp/railway-single-{id(self)}-nodes.json",
                        state_path=f"/tmp/railway-single-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post_json(self, manager, path, payload, token=True):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        raw = json.dumps(payload).encode()
        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: {len(raw)}\r\n"
                   + (f"Authorization: Bearer {self.TOKEN}\r\n" if token else ""))
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1") + raw)
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": None,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}"}}
                          for i, ip in enumerate(ips)]

    def test_probe_rejects_missing_token(self) -> None:
        manager = self._manager()
        try:
            status_line, _ = self._post_json(manager, "/api/probe",
                                             {"tag": "vpngate-0"}, token=False)
        finally:
            manager.stop()

        self.assertIn("401", status_line)

    def test_probe_unknown_tag_returns_404(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, body = self._post_json(manager, "/api/probe",
                                                {"tag": "vpngate-9"})
        finally:
            manager.stop()

        self.assertIn("404", status_line)
        self.assertFalse(json.loads(body.decode())["ok"])

    def test_probe_missing_tag_returns_400(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, _ = self._post_json(manager, "/api/probe", {})
        finally:
            manager.stop()

        self.assertIn("400", status_line)

    def test_probe_dials_only_the_requested_node(self) -> None:
        calls = []
        manager = self._manager(
            dial_fn=lambda node: calls.append(node["server"]) or 123)
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            status_line, body = self._post_json(manager, "/api/probe",
                                                {"tag": "vpngate-1"})
            manager._single_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertIn("202", status_line)
        self.assertTrue(json.loads(body.decode())["accepted"])
        self.assertEqual(["203.0.113.12"], calls)
        self.assertIsNone(manager._nodes[0]["real_latency_ms"])
        self.assertEqual(123, manager._nodes[1]["real_latency_ms"])
        probe = manager.status["probe"]
        self.assertEqual("done", probe["state"])
        self.assertEqual("vpngate-1", probe["tag"])
        self.assertEqual(123, probe["ms"])

    def test_probe_failure_keeps_none_and_records_error(self) -> None:
        def _boom(node):
            raise RuntimeError("tunnel down")

        manager = self._manager(dial_fn=_boom)
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, _ = self._post_json(manager, "/api/probe",
                                             {"tag": "vpngate-0"})
            manager._single_probe_thread.join(timeout=30)
            history = [h["event"] for h in manager.status["refresh_history"]]
        finally:
            manager.stop()

        self.assertIn("202", status_line)
        self.assertIsNone(manager._nodes[0]["real_latency_ms"])
        self.assertEqual("done", manager.status["probe"]["state"])
        self.assertTrue(manager.status["probe"]["error"])
        self.assertIn("single-probe", history)


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


class AstraUiTests(unittest.TestCase):
    """Astra-style /ui: hero kicker, pills, bench table, verify CTA."""

    def test_hero_kicker_and_verify_cta_present(self) -> None:
        self.assertIn('id="hero-kicker"', UI_HTML)
        self.assertIn('id="btn-verify"', UI_HTML)
        self.assertIn('id="btn-refresh"', UI_HTML)

    def test_pills_and_bench_table_present(self) -> None:
        self.assertIn('id="pills"', UI_HTML)
        self.assertIn('id="bench-body"', UI_HTML)
        self.assertIn('id="history-line"', UI_HTML)

    def test_api_contract_preserved(self) -> None:
        self.assertIn("/api/status", UI_HTML)
        self.assertIn("/api/switch", UI_HTML)
        self.assertIn("/api/refresh", UI_HTML)
        self.assertIn("Authorization", UI_HTML)

    def test_dark_theme_and_nav_present(self) -> None:
        self.assertIn('id="topnav"', UI_HTML)
        self.assertIn("background:#000", UI_HTML)

    def test_full_probe_button_present(self) -> None:
        self.assertIn('id="btn-fullprobe"', UI_HTML)
        self.assertIn("fullProbeNow", UI_HTML)
        self.assertIn("/api/full_probe", UI_HTML)

    def test_single_probe_button_calls_api_probe(self) -> None:
        start = UI_HTML.index("async function probeOne")
        block = UI_HTML[start:start + 600]
        self.assertIn("/api/probe", block)


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

    def test_missing_proxy_pass_is_generated(self) -> None:
        env = {"PORT": "8080", "PROXY_USER": "u"}
        config = build_config_from_env(env)

        self.assertGreaterEqual(len(config["password"]), 16)

    def test_missing_proxy_pass_generates_unique_values(self) -> None:
        env = {"PORT": "8080", "PROXY_USER": "u"}
        first = build_config_from_env(dict(env))["password"]
        second = build_config_from_env(dict(env))["password"]

        self.assertNotEqual(first, second)

    def test_non_https_snapshot_url_exits_nonzero(self) -> None:
        with self.assertRaises(SystemExit):
            build_config_from_env(self._env(SNAPSHOT_URL="http://example.com/x.csv"))

    def test_valid_env_builds_config(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(8080, config["port"])
        self.assertEqual("0123456789abcdef", config["password"])

    def test_data_dir_defaults_to_cwd(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(".", config["data_dir"])

    def test_data_dir_passthrough(self) -> None:
        config = build_config_from_env(self._env(DATA_DIR="/data"))

        self.assertEqual("/data", config["data_dir"])

    def test_limit_defaults_to_all(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(0, config["limit"])

    def test_real_topk_defaults_to_thirty(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(30, config["real_topk"])

    def test_missing_admin_token_defaults_to_vpn(self) -> None:
        env = {"PORT": "8080", "PROXY_USER": "u", "PROXY_PASS": "0123456789abcdef"}
        config = build_config_from_env(env)

        self.assertEqual("vpn", config["admin_token"])
        self.assertFalse(config["admin_token_generated"])

    def test_explicit_admin_token_is_kept(self) -> None:
        config = build_config_from_env(self._env(ADMIN_TOKEN="my-own-admin-token-0123456789"))

        self.assertEqual("my-own-admin-token-0123456789", config["admin_token"])

    def test_disguise_path_defaults_to_empty(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual("", config["disguise_path"])

    def test_disguise_path_passthrough(self) -> None:
        config = build_config_from_env(self._env(DISGUISE_PATH="/app/www/index.html"))

        self.assertEqual("/app/www/index.html", config["disguise_path"])

    def test_default_fetch_rejects_plain_http(self) -> None:
        with self.assertRaises(ValueError):
            default_fetch("http://example.com/x.csv", timeout=1)

    def test_dial_workers_defaults_to_ten(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(10, config["dial_workers"])

    def test_dial_workers_env_override(self) -> None:
        config = build_config_from_env(self._env(DIAL_WORKERS="4"))

        self.assertEqual(4, config["dial_workers"])

    def test_data_dir_prefers_railway_volume(self) -> None:
        config = build_config_from_env(
            self._env(RAILWAY_VOLUME_MOUNT_PATH="/data"))

        self.assertEqual("/data", config["data_dir"])

    def test_explicit_data_dir_beats_railway_volume(self) -> None:
        config = build_config_from_env(self._env(
            DATA_DIR="/custom", RAILWAY_VOLUME_MOUNT_PATH="/data"))

        self.assertEqual("/custom", config["data_dir"])


class DialWorkersPlumbingTests(unittest.TestCase):
    """refresh_once must forward the configured dial concurrency."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def test_refresh_once_forwards_dial_workers(self) -> None:
        seen = {}
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(), start_singbox=False,
            auto_refresh=False, fetch_on_start=False,
            admin_token=self.TOKEN, dial_workers=10,
            config_path=f"/tmp/railway-dw-{id(self)}.json",
            nodes_path=f"/tmp/railway-dw-{id(self)}-nodes.json",
            state_path=f"/tmp/railway-dw-{id(self)}-state.json")
        try:
            with mock.patch("railway_manager.snapshot_to_nodes",
                            side_effect=lambda *a, **k: seen.update(k) or []):
                manager.refresh_once(fetcher=lambda url, timeout: "x")
        finally:
            manager.stop()

        self.assertEqual(10, seen.get("dial_workers"))


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


class StartOrderTests(unittest.TestCase):
    TOKEN = "0123456789abcdef-start-order"

    def _get(self, port: int, path: str) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_listener_up_while_initial_refresh_blocked(self) -> None:
        gate = threading.Event()
        with tempfile.TemporaryDirectory() as tmpdir:
            def blocking_fetch(url, timeout):
                gate.wait(30)
                return _snapshot_csv("203.0.113.11")

            manager = RailwayManager(
                port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
                start_singbox=False, auto_refresh=False, fetch_on_start=True,
                config_path=f"{tmpdir}/singbox.json",
                nodes_path=f"{tmpdir}/nodes.json",
                state_path=f"{tmpdir}/state.json",
                fetcher=blocking_fetch)
            started = time.monotonic()
            port = manager.start()
            try:
                # start() must return while the first refresh is still blocked
                self.assertLess(time.monotonic() - started, 5)
                with mock.patch.object(RailwayManager, "_check_config",
                                       return_value=True):
                    with mock.patch("railway_manager.probe_tcp_latency",
                                      return_value=100):
                        # listener already accepts: 503, no endpoints yet
                        self.assertIn(b"503", self._get(port, "/healthz"))
                        gate.set()
                        deadline = time.monotonic() + 15
                        while (manager.status["last_refresh"] is None
                               and time.monotonic() < deadline):
                            time.sleep(0.2)
                        self.assertIsNotNone(manager.status["last_refresh"])
            finally:
                gate.set()
                manager.stop()


class SwitchRealLatencyTests(unittest.TestCase):
    TOKEN = "0123456789abcdef-switch-real"

    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
                        start_singbox=True, auto_refresh=False, fetch_on_start=False,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json",
                        fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11",
                                                                   "203.0.113.12"))
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, port: int, path: str, body: bytes) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            headers = (f"POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                       f"Authorization: Bearer {self.TOKEN}\r\n"
                       f"Content-Length: {len(body)}\r\n")
            sock.sendall(headers.encode() + b"\r\n" + body)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_switch_by_country_prefers_real_latency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # handshake winner is .11, but real tunnel latency winner is .12
            dial = lambda node: {"203.0.113.11": 800, "203.0.113.12": 50}[node["server"]]
            manager = self._manager(tmpdir, real_topk=2, dial_fn=dial)
            port = manager.start()
            try:
                with _fake_singbox():
                    with mock.patch(
                            "railway_manager.probe_tcp_latency",
                            side_effect=lambda h, p, timeout=5: (
                                100 if h == "203.0.113.11" else 900)):
                        self.assertTrue(manager.refresh_once())
                    tag12 = next(e["tag"] for e in manager.status["endpoints"]
                                 if e["server"] == "203.0.113.12")
                    body = json.dumps({"country": "JP"}).encode()
                    response = self._post(port, "/api/switch", body)

                self.assertIn(b"200 OK", response)
                self.assertEqual(tag12, manager.preferred_tag)
            finally:
                manager.stop()


class ColdStartTests(unittest.TestCase):
    def _paths(self, tmpdir: str) -> dict:
        return dict(config_path=f"{tmpdir}/singbox.json",
                    nodes_path=f"{tmpdir}/nodes.json",
                    state_path=f"{tmpdir}/state.json")

    def _seed_last_good(self, tmpdir: str) -> None:
        seed = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            **self._paths(tmpdir))
        nodes = snapshot_to_nodes(
            _snapshot_csv("203.0.113.21", "203.0.113.22"), probe=False)
        seed._nodes = nodes
        seed._persist_nodes()
        endpoints = nodes_to_endpoints(nodes)
        with open(seed.last_good_path, "w", encoding="utf-8") as handle:
            json.dump(build_singbox_config(endpoints, "127.0.0.1",
                                          seed.mixed_port), handle)

    def test_boot_attempted_before_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = RailwayManager(
                port=0, mixed_port=get_free_port(),
                start_singbox=False, auto_refresh=False, fetch_on_start=False,
                **self._paths(tmpdir))
            calls = []
            with mock.patch.object(
                    RailwayManager, "_boot_from_last_good",
                    side_effect=lambda: calls.append("boot") or True), \
                 mock.patch.object(
                    RailwayManager, "refresh_once",
                    side_effect=lambda: calls.append("refresh") or True):
                manager._initial_refresh()
            self.assertEqual(["boot", "refresh"], calls)

    def test_serves_last_good_while_refresh_in_flight(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._seed_last_good(tmpdir)
            manager = RailwayManager(
                port=0, mixed_port=get_free_port(),
                start_singbox=False, auto_refresh=False, fetch_on_start=False,
                **self._paths(tmpdir))
            gate = threading.Event()
            entered = threading.Event()

            def slow_refresh():
                entered.set()
                gate.wait(30)
                return True

            try:
                with mock.patch.object(RailwayManager, "refresh_once",
                                       side_effect=slow_refresh):
                    thread = threading.Thread(target=manager._initial_refresh,
                                              daemon=True)
                    thread.start()
                    self.assertTrue(entered.wait(10))
                    deadline = time.monotonic() + 10
                    while not manager.status["endpoints"] \
                            and time.monotonic() < deadline:
                        time.sleep(0.1)
                    self.assertTrue(manager.status["endpoints"],
                                    "last-good not served while refresh in flight")
                    self.assertTrue(manager._healthy())
                    self.assertTrue(thread.is_alive(),
                                    "refresh should still be running")
            finally:
                gate.set()

    def test_no_last_good_no_endpoints_stays_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = RailwayManager(
                port=0, mixed_port=get_free_port(),
                start_singbox=False, auto_refresh=False, fetch_on_start=False,
                **self._paths(tmpdir))
            with mock.patch.object(RailwayManager, "refresh_once",
                                   return_value=False):
                manager._initial_refresh()
            self.assertFalse(manager._healthy())
            self.assertEqual([], manager.status["endpoints"])


class TunnelTests(unittest.TestCase):
    def _paths(self, tmpdir: str) -> dict:
        return {"config_path": os.path.join(tmpdir, "singbox.json"),
                "nodes_path": os.path.join(tmpdir, "nodes.json"),
                "state_path": os.path.join(tmpdir, "state.json")}

    def _manager(self, tmpdir: str, **kwargs) -> RailwayManager:
        defaults = dict(port=0, mixed_port=get_free_port(),
                        start_singbox=False, auto_refresh=False,
                        fetch_on_start=False)
        defaults.update(kwargs)
        return RailwayManager(**defaults, **self._paths(tmpdir))

    def test_env_defaults_leave_tunnel_off(self) -> None:
        cfg = build_config_from_env({"PROXY_PASS": "0123456789abcdef"})
        self.assertEqual("", cfg["vless_uuid"])
        self.assertEqual("", cfg["tunnel_token"])

    def test_env_picks_up_uuid_and_token(self) -> None:
        cfg = build_config_from_env({"PROXY_PASS": "0123456789abcdef",
                                     "VLESS_UUID": "u-u-i-d",
                                     "TUNNEL_TOKEN": "t-o-k-e-n"})
        self.assertEqual("u-u-i-d", cfg["vless_uuid"])
        self.assertEqual("t-o-k-e-n", cfg["tunnel_token"])

    def test_apply_config_includes_vless_when_uuid_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, vless_uuid="u-u-i-d")
            node = {"server": "203.0.113.1", "server_port": 443,
                    "endpoint": ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")}
            manager._nodes = [node]
            with _fake_singbox(), \
                 mock.patch.object(RailwayManager, "_restart_singbox"):
                self.assertTrue(manager._apply_config(final="auto"))
            written = _read_json(manager.config_path)
            tags = [i["tag"] for i in written["inbounds"]]
            self.assertIn("vless-direct", tags)
            self.assertIn("vless-chain", tags)

    def test_apply_config_skips_vless_without_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            node = {"server": "203.0.113.1", "server_port": 443,
                    "endpoint": ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")}
            manager._nodes = [node]
            with _fake_singbox(), \
                 mock.patch.object(RailwayManager, "_restart_singbox"):
                self.assertTrue(manager._apply_config(final="auto"))
            written = _read_json(manager.config_path)
            tags = [i["tag"] for i in written.get("inbounds", [])]
            self.assertNotIn("vless-direct", tags)

    def test_start_cloudflared_without_token_skips_softly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, tunnel_token="")
            with mock.patch("railway_manager.subprocess.Popen") as popen:
                self.assertFalse(manager._start_cloudflared())
                popen.assert_not_called()
            self.assertIsNone(manager._cloudflared_proc)
            self.assertEqual("no-token", manager.status["tunnel"]["state"])

    def test_start_cloudflared_missing_binary_skips_softly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, tunnel_token="t-o-k-e-n",
                                    cloudflared_bin="/nonexistent/cloudflared")
            with mock.patch("railway_manager.subprocess.Popen") as popen:
                self.assertFalse(manager._start_cloudflared())
                popen.assert_not_called()
            self.assertEqual("no-binary", manager.status["tunnel"]["state"])

    def test_start_cloudflared_spawns_process_with_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, tunnel_token="t-o-k-e-n")
            with mock.patch("railway_manager.subprocess.Popen") as popen, \
                 mock.patch("railway_manager.shutil.which",
                            return_value="/usr/local/bin/cloudflared"):
                self.assertTrue(manager._start_cloudflared())
                args = popen.call_args[0][0]
                self.assertIn("t-o-k-e-n", args)
            self.assertEqual("running", manager.status["tunnel"]["state"])


class OnclickQuoteTests(unittest.TestCase):
    """Row actions pass the tag via data attributes + delegation (never
    inline onclick with Python-eaten backslash quotes)."""

    def test_probe_action_uses_data_attribute(self) -> None:
        self.assertIn("data-probe='", UI_HTML)

    def test_switch_action_uses_data_attribute(self) -> None:
        self.assertIn("data-switch='", UI_HTML)

    def test_delegation_handler_reads_data_attributes(self) -> None:
        self.assertIn('getAttribute("data-probe")', UI_HTML)
        self.assertIn('getAttribute("data-switch")', UI_HTML)


class GlassUiTests(unittest.TestCase):
    """Glassmorphism console structure + feedback affordances."""

    def test_glass_cards_present(self) -> None:
        self.assertIn("glass-card", UI_HTML)

    def test_exit_card_present(self) -> None:
        self.assertIn('id="exit-card"', UI_HTML)

    def test_verify_button_present(self) -> None:
        self.assertIn('id="btn-verify"', UI_HTML)
        self.assertIn("verifyExit(", UI_HTML)

    def test_toast_container_present(self) -> None:
        self.assertIn('id="toast"', UI_HTML)

    def test_history_list_present(self) -> None:
        self.assertIn('id="history-list"', UI_HTML)

    def test_node_search_present(self) -> None:
        self.assertIn('id="node-search"', UI_HTML)

    def test_probe_progress_present(self) -> None:
        self.assertIn('id="probe-progress"', UI_HTML)

    def test_toast_helper_present(self) -> None:
        self.assertIn("function toast(", UI_HTML)

    def test_busy_helper_present(self) -> None:
        self.assertIn("function setBusy(", UI_HTML)

    def test_verify_exit_fn_present(self) -> None:
        self.assertIn("verifyExit(", UI_HTML)

    def test_served_js_parses(self) -> None:
        """Extract <script> from the RUNTIME UI_HTML (post-Python-unescape)
        and run node --check: catches backslash-quote breakage that a
        source-level check would miss."""
        node = shutil.which("node")
        if node is None:
            self.skipTest("node not installed")
        match = re.search(r"<script>(.*)</script>", UI_HTML, re.S)
        self.assertIsNotNone(match)
        with tempfile.NamedTemporaryFile("w", suffix=".js",
                                         delete=False,
                                         encoding="utf-8") as handle:
            handle.write(match.group(1))
            path = handle.name
        try:
            result = subprocess.run([node, "--check", path],
                                    capture_output=True, text=True,
                                    timeout=60)
        finally:
            os.unlink(path)
        self.assertEqual(0, result.returncode, result.stderr)


class LoginGateTests(unittest.TestCase):
    """Token login gate: enter token first, console hidden until verified."""

    def test_login_gate_present(self) -> None:
        self.assertIn('id="login-gate"', UI_HTML)

    def test_login_input_and_button_present(self) -> None:
        self.assertIn('id="login-token"', UI_HTML)
        self.assertIn('id="btn-login"', UI_HTML)
        self.assertIn("loginEnter(", UI_HTML)

    def test_lock_button_present(self) -> None:
        self.assertIn('id="btn-lock"', UI_HTML)

    def test_silent_login_present(self) -> None:
        self.assertIn("silentLogin(", UI_HTML)

    def test_topnav_token_input_removed(self) -> None:
        self.assertNotIn('id="token"', UI_HTML)


class VerifyApiTests(unittest.TestCase):
    """POST /api/verify measures the real exit IP through the live chain."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"/tmp/railway-verify-{id(self)}.json",
                        nodes_path=f"/tmp/railway-verify-{id(self)}-nodes.json",
                        state_path=f"/tmp/railway-verify-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path, token=True):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   + (f"Authorization: Bearer {self.TOKEN}\r\n" if token else ""))
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": None,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}"}}
                          for i, ip in enumerate(ips)]

    def test_verify_rejects_missing_token(self) -> None:
        manager = self._manager()
        try:
            status_line, _ = self._post(manager, "/api/verify", token=False)
        finally:
            manager.stop()

        self.assertIn("401", status_line)

    def test_verify_accepts_and_reports_exit_ip(self) -> None:
        manager = self._manager(
            verify_fn=lambda endpoint: ("203.0.113.99", 321))
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, body = self._post(manager, "/api/verify", token=True)
            accepted_state = manager.status["verify"]["state"]
            manager._verify_thread.join(timeout=30)
            final = manager.status["verify"]
        finally:
            manager.stop()

        self.assertIn("202", status_line)
        self.assertTrue(json.loads(body.decode())["accepted"])
        self.assertEqual("running", accepted_state)
        self.assertEqual("done", final["state"])
        self.assertEqual("203.0.113.99", final["exit_ip"])
        self.assertEqual(321, final["ms"])
        self.assertEqual("vpngate-0", final["via_tag"])

    def test_verify_without_nodes_returns_503(self) -> None:
        manager = self._manager(
            verify_fn=lambda endpoint: ("203.0.113.99", 321))
        try:
            status_line, _ = self._post(manager, "/api/verify", token=True)
        finally:
            manager.stop()

        self.assertIn("503", status_line)


if __name__ == "__main__":
    unittest.main()
