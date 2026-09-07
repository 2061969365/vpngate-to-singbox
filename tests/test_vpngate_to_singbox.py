"""RED test for minimal VPNGate .ovpn -> sing-box openvpn-client converter."""
import unittest

from vpngate_to_singbox import ovpn_to_endpoint


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


if __name__ == "__main__":
    unittest.main()
