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
