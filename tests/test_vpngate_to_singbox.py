"""Tests for minimal VPNGate .ovpn -> sing-box openvpn-client converter."""
import base64
import socket
import threading
import unittest

from vpngate_to_singbox import (
    build_singbox_config,
    nodes_to_endpoints,
    ovpn_to_endpoint,
    probe_tcp_latency,
    snapshot_to_endpoints,
    snapshot_to_nodes,
)


TCP_OVPN = """\
client
dev tun
proto tcp-client
remote 203.0.113.1 443 tcp
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
auth SHA1
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
Q0E=
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
Q0VSVA==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
S0VZ
-----END PRIVATE KEY-----
</key>
"""

UDP_ONLY_OVPN = """\
client
dev tun
proto udp
remote 198.51.100.7 1194 udp
<ca>
Q0E=
</ca>
"""


class ConvertTcpTests(unittest.TestCase):
    def test_tcp_config_converts_to_openvpn_client_endpoint(self) -> None:
        ep = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")

        self.assertEqual("openvpn-client", ep["type"])
        self.assertEqual("vpngate-0", ep["tag"])
        self.assertEqual("203.0.113.1", ep["server"])
        self.assertEqual(443, ep["server_port"])
        self.assertEqual("tcp", ep["network"])
        self.assertFalse(ep["system"])
        self.assertEqual("vpn", ep["username"])
        self.assertEqual("vpn", ep["password"])
        self.assertIn("BF-CBC", ep["data_ciphers"])
        self.assertIn("AES-128-CBC", ep["data_ciphers"])
        self.assertEqual("SHA1", ep["auth"])
        self.assertIn("BEGIN CERTIFICATE", ep["tls"]["certificate"])

    def test_udp_only_config_raises(self) -> None:
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(UDP_ONLY_OVPN, tag="vpngate-x")


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _snapshot_row(host: str, ip: str, speed: int, config_b64: str) -> str:
    return f"{host},{ip},100,20,{speed},Japan,JP,1,{config_b64}"


def _snapshot_row_country(host: str, ip: str, speed: int, config_b64: str,
                          country_long: str, country_short: str) -> str:
    return f"{host},{ip},100,20,{speed},{country_long},{country_short},1,{config_b64}"


CSV_HEADER = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"


class ProbeTcpLatencyTests(unittest.TestCase):
    def test_closed_port_returns_zero(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
        sock.close()

        self.assertEqual(0, probe_tcp_latency("127.0.0.1", free_port, timeout=2))

    def test_listening_port_returns_positive_ms(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def _accept() -> None:
            listener.settimeout(5)
            try:
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                        conn.close()
                    except socket.timeout:
                        continue
            except OSError:
                pass

        worker = threading.Thread(target=_accept, daemon=True)
        worker.start()
        try:
            latency = probe_tcp_latency("127.0.0.1", port, timeout=5)
        finally:
            stop.set()
            listener.close()

        self.assertGreater(latency, 0)


class SnapshotToNodesTests(unittest.TestCase):
    def _csv(self) -> str:
        return "\n".join([
            CSV_HEADER,
            _snapshot_row_country("vpn-jp-slow", "203.0.113.11", 1000,
                                  _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.11")),
                                  "Japan", "JP"),
            _snapshot_row_country("vpn-us-fast", "203.0.113.12", 500,
                                  _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.12")),
                                  "United States", "US"),
            # UDP-only row must be skipped even though its Speed is highest.
            _snapshot_row_country("vpn-udp", "198.51.100.99", 999999,
                                  _b64(UDP_ONLY_OVPN), "Japan", "JP"),
            _snapshot_row_country("vpn-broken", "203.0.113.13", 8000,
                                  "!!!not-base64!!!", "Japan", "JP"),
            "*vpn_servers",
            "# 123",
        ]) + "\n"

    def test_nodes_carry_country_and_latency_sorted_by_latency(self) -> None:
        latencies = {"203.0.113.11": 900, "203.0.113.12": 100}

        nodes = snapshot_to_nodes(
            self._csv(), probe_fn=lambda host, port: latencies[host])

        self.assertEqual(2, len(nodes))
        # sorted by measured latency, not by Speed
        self.assertEqual("203.0.113.12", nodes[0]["server"])
        self.assertEqual("US", nodes[0]["country_short"])
        self.assertEqual("United States", nodes[0]["country"])
        self.assertEqual(100, nodes[0]["latency_ms"])
        self.assertEqual(500, nodes[0]["speed"])
        self.assertEqual("JP", nodes[1]["country_short"])

    def test_unreachable_probe_result_is_filtered_out(self) -> None:
        nodes = snapshot_to_nodes(self._csv(), probe_fn=lambda host, port: 0)

        self.assertEqual([], nodes)

    def test_probe_disabled_falls_back_to_speed_rank(self) -> None:
        nodes = snapshot_to_nodes(self._csv(), probe=False)

        self.assertEqual(2, len(nodes))
        self.assertEqual("203.0.113.11", nodes[0]["server"])
        self.assertIsNone(nodes[0]["latency_ms"])


class NodesToEndpointsTests(unittest.TestCase):
    def test_endpoint_dict_has_no_extra_metadata_keys(self) -> None:
        nodes = snapshot_to_nodes(
            "\n".join([
                CSV_HEADER,
                _snapshot_row_country("vpn-jp", "203.0.113.11", 1000,
                                      _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.11")),
                                      "Japan", "JP"),
            ]) + "\n",
            probe_fn=lambda host, port: 50,
        )

        endpoints = nodes_to_endpoints(nodes, tag_prefix="vpngate")

        self.assertEqual(1, len(endpoints))
        self.assertEqual("vpngate-0", endpoints[0]["tag"])
        self.assertNotIn("country", endpoints[0])
        self.assertNotIn("country_short", endpoints[0])
        self.assertNotIn("latency_ms", endpoints[0])
        self.assertNotIn("speed", endpoints[0])


class FailoverConfigTests(unittest.TestCase):
    def test_urltest_covers_direct_and_tuned_params(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint], final="auto")

        self.assertEqual("auto", cfg["route"]["final"])
        urltest = next(o for o in cfg["outbounds"] if o["type"] == "urltest")
        self.assertIn("direct", urltest["outbounds"])
        self.assertIn("vpngate-0", urltest["outbounds"])
        self.assertEqual("1m", urltest["interval"])
        self.assertEqual(800, urltest["tolerance"])

    def test_default_final_is_auto(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint])

        self.assertEqual("auto", cfg["route"]["final"])


class SnapshotToEndpointsTests(unittest.TestCase):
    def test_tcp_rows_convert_udp_and_broken_skipped_ranked_by_speed(self) -> None:
        slow_tcp = TCP_OVPN.replace("203.0.113.1", "203.0.113.11")
        fast_tcp = TCP_OVPN.replace("203.0.113.1", "203.0.113.12")
        csv_text = "\n".join(
            [
                "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64",
                # UDP row is fastest but must be skipped (no TCP remote)
                _snapshot_row("vpn-udp", "198.51.100.99", 999999, _b64(UDP_ONLY_OVPN)),
                _snapshot_row("vpn-slow", "203.0.113.11", 1000, _b64(slow_tcp)),
                _snapshot_row("vpn-fast", "203.0.113.12", 5000, _b64(fast_tcp)),
                _snapshot_row("vpn-broken", "203.0.113.13", 8000, "!!!not-base64!!!"),
                "*vpn_servers",
                "# 123",
            ]
        ) + "\n"

        endpoints = snapshot_to_endpoints(csv_text, limit=8, tag_prefix="vpngate",
                                            probe=False)

        self.assertEqual(2, len(endpoints))
        # ranked by Speed desc
        self.assertEqual("203.0.113.12", endpoints[0]["server"])
        self.assertEqual("203.0.113.11", endpoints[1]["server"])
        self.assertEqual(["vpngate-0", "vpngate-1"], [ep["tag"] for ep in endpoints])
        self.assertTrue(all(ep["network"] == "tcp" for ep in endpoints))

    def test_limit_is_respected(self) -> None:
        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", 1000 + i,
                          _b64(TCP_OVPN.replace("203.0.113.1", f"203.0.113.{100 + i}")))
            for i in range(5)
        ]
        csv_text = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n" + "\n".join(rows) + "\n"

        endpoints = snapshot_to_endpoints(csv_text, limit=2, probe=False)

        self.assertEqual(2, len(endpoints))

    def test_snapshot_without_usable_tcp_raises(self) -> None:
        csv_text = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n"
            + _snapshot_row("vpn-udp", "198.51.100.99", 999999, _b64(UDP_ONLY_OVPN))
            + "\n"
        )

        with self.assertRaises(ValueError):
            snapshot_to_endpoints(csv_text, probe=False)


class FakeSocks5Server:
    """Minimal SOCKS5 server: no-auth + CONNECT success + fixed HTTP status."""

    def __init__(self, status_code: int = 204) -> None:
        self.status_code = status_code
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(5)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass

    def _recvn(self, conn: socket.socket, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise OSError("eof")
            data += chunk
        return data

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                nmethods = self._recvn(conn, 2)[1]
                self._recvn(conn, nmethods)
                conn.sendall(b"\x05\x00")
                header = self._recvn(conn, 4)
                atyp = header[3]
                if atyp == 1:
                    self._recvn(conn, 6)
                elif atyp == 3:
                    self._recvn(conn, self._recvn(conn, 1)[0] + 2)
                elif atyp == 4:
                    self._recvn(conn, 18)
                else:
                    conn.close()
                    continue
                conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                conn.sendall(
                    f"HTTP/1.1 {self.status_code} Test\r\nContent-Length: 0\r\n"
                    f"Connection: close\r\n\r\n".encode()
                )
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass


class Socks5LatencyTests(unittest.TestCase):
    def test_204_returns_positive_ms(self) -> None:
        from vpngate_to_singbox import _socks5_get_latency_ms

        server = FakeSocks5Server(status_code=204)
        server.start()
        try:
            latency = _socks5_get_latency_ms("127.0.0.1", server.port, timeout=5)
        finally:
            server.stop()

        self.assertIsNotNone(latency)
        self.assertGreaterEqual(latency, 1)

    def test_non_204_returns_none(self) -> None:
        from vpngate_to_singbox import _socks5_get_latency_ms

        server = FakeSocks5Server(status_code=500)
        server.start()
        try:
            latency = _socks5_get_latency_ms("127.0.0.1", server.port, timeout=5)
        finally:
            server.stop()

        self.assertIsNone(latency)

    def test_refused_connection_returns_none(self) -> None:
        from vpngate_to_singbox import _socks5_get_latency_ms

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
        sock.close()

        self.assertIsNone(_socks5_get_latency_ms("127.0.0.1", free_port, timeout=2))


def _real_csv() -> str:
    return "\n".join([
        CSV_HEADER,
        _snapshot_row_country("vpn-a", "203.0.113.21", 3000,
                              _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.21")),
                              "Japan", "JP"),
        _snapshot_row_country("vpn-b", "203.0.113.22", 2000,
                              _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.22")),
                              "Japan", "JP"),
        _snapshot_row_country("vpn-c", "203.0.113.23", 1000,
                              _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.23")),
                              "Japan", "JP"),
    ]) + "\n"


class RealTopKTests(unittest.TestCase):
    def test_measured_first_then_unmeasured_by_handshake(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        handshakes = {"203.0.113.21": 300, "203.0.113.22": 100, "203.0.113.23": 200}
        real = {"203.0.113.22": 500, "203.0.113.23": 50}

        nodes = snapshot_to_nodes(
            _real_csv(),
            probe_fn=lambda host, port: handshakes[host],
            real_topk=2,
            dial_fn=lambda node: real.get(node["server"]),
        )

        self.assertEqual(["203.0.113.23", "203.0.113.22", "203.0.113.21"],
                         [n["server"] for n in nodes])
        self.assertEqual([50, 500, None],
                         [n["real_latency_ms"] for n in nodes])

    def test_real_topk_zero_never_dials(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        calls: list = []
        nodes = snapshot_to_nodes(
            _real_csv(),
            probe_fn=lambda host, port: 100,
            real_topk=0,
            dial_fn=lambda node: calls.append(node["server"]) or 1,
        )

        self.assertEqual([], calls)
        self.assertTrue(all(n["real_latency_ms"] is None for n in nodes))

    def test_dial_exception_treated_as_unmeasured(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        def bad_dial(node):
            if node["server"] == "203.0.113.22":
                raise RuntimeError("tunnel down")
            return 70

        nodes = snapshot_to_nodes(
            _real_csv(),
            probe_fn=lambda host, port: 100,
            real_topk=3,
            dial_fn=bad_dial,
        )

        by_server = {n["server"]: n for n in nodes}
        self.assertIsNone(by_server["203.0.113.22"]["real_latency_ms"])
        self.assertEqual(70, by_server["203.0.113.21"]["real_latency_ms"])
        # measured nodes rank before the failed one
        self.assertLess(
            [n["server"] for n in nodes].index("203.0.113.21"),
            [n["server"] for n in nodes].index("203.0.113.22"),
        )

    def test_limit_zero_returns_all_nodes(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", 1000 + i,
                          _b64(TCP_OVPN.replace("203.0.113.1", f"203.0.113.{100 + i}")))
            for i in range(5)
        ]
        csv_text = CSV_HEADER + "\n" + "\n".join(rows) + "\n"

        self.assertEqual(5, len(snapshot_to_nodes(csv_text, limit=0, probe=False)))

    def test_default_limit_returns_all_nodes(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", 1000 + i,
                          _b64(TCP_OVPN.replace("203.0.113.1", f"203.0.113.{100 + i}")))
            for i in range(5)
        ]
        csv_text = CSV_HEADER + "\n" + "\n".join(rows) + "\n"

        self.assertEqual(5, len(snapshot_to_nodes(csv_text, probe=False)))


class MixedInboundTests(unittest.TestCase):
    def test_mixed_inbound_included_when_requested(self) -> None:
        from vpngate_to_singbox import build_singbox_config, ovpn_to_endpoint

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint], mixed_listen="127.0.0.1", mixed_port=18080)

        inbounds = cfg.get("inbounds", [])
        self.assertEqual(1, len(inbounds))
        self.assertEqual("mixed", inbounds[0]["type"])
        self.assertEqual("127.0.0.1", inbounds[0]["listen"])
        self.assertEqual(18080, inbounds[0]["listen_port"])

    def test_no_inbound_by_default(self) -> None:
        from vpngate_to_singbox import build_singbox_config, ovpn_to_endpoint

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint])

        self.assertNotIn("inbounds", cfg)


if __name__ == "__main__":
    unittest.main()
