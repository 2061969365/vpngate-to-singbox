"""Tests for minimal VPNGate .ovpn -> sing-box openvpn-client converter."""
import base64
import unittest

from vpngate_to_singbox import ovpn_to_endpoint, snapshot_to_endpoints


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

        endpoints = snapshot_to_endpoints(csv_text, limit=8, tag_prefix="vpngate")

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

        endpoints = snapshot_to_endpoints(csv_text, limit=2)

        self.assertEqual(2, len(endpoints))

    def test_snapshot_without_usable_tcp_raises(self) -> None:
        csv_text = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n"
            + _snapshot_row("vpn-udp", "198.51.100.99", 999999, _b64(UDP_ONLY_OVPN))
            + "\n"
        )

        with self.assertRaises(ValueError):
            snapshot_to_endpoints(csv_text)


if __name__ == "__main__":
    unittest.main()
