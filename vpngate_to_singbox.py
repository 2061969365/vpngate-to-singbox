"""Minimal VPNGate .ovpn -> sing-box openvpn-client converter (stdlib only)."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DEFAULT_USERNAME = "vpn"
DEFAULT_PASSWORD = "vpn"
# VPNGate uses legacy crypto; sing-box >= 1.14 defaults to AEAD only,
# so the old ciphers must be listed explicitly.
DEFAULT_DATA_CIPHERS = ["AES-128-CBC", "AES-256-CBC", "BF-CBC"]
DEFAULT_AUTH = "SHA1"

_BLOCK_RE = re.compile(r"<(ca|cert|key|tls-auth|tls-crypt)>(.*?)</\1>", re.IGNORECASE | re.DOTALL)
_REMOTE_RE = re.compile(r"^\s*remote\s+(\S+)\s+(\d+)(?:\s+(\S+))?\s*$", re.IGNORECASE | re.MULTILINE)
_PROTO_RE = re.compile(r"^\s*proto\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_AUTH_RE = re.compile(r"^\s*auth\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_CIPHER_RE = re.compile(r"^\s*cipher\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)


def _is_tcp_proto(proto: str) -> bool:
    return proto.lower().startswith("tcp")


def _pick_tcp_remote(config_text: str) -> tuple[str, int]:
    global_protos = [m.group(1) for m in _PROTO_RE.finditer(config_text)]
    global_tcp = any(_is_tcp_proto(p) for p in global_protos)
    remotes = [(m.group(1), int(m.group(2)), (m.group(3) or "")) for m in _REMOTE_RE.finditer(config_text)]
    if not remotes:
        raise ValueError("no remote directive found")
    for host, port, proto in remotes:
        if proto and _is_tcp_proto(proto):
            return host, port
    if global_tcp:
        for host, port, proto in remotes:
            if not proto or not proto.lower().startswith("udp"):
                return host, port
    raise ValueError("no TCP remote found (only UDP available)")


def ovpn_to_endpoint(
    config_text: str,
    tag: str,
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
) -> dict:
    """Convert one OpenVPN client config (TCP) to a sing-box openvpn-client endpoint."""
    if not config_text or not config_text.strip():
        raise ValueError("empty openvpn config")
    server, server_port = _pick_tcp_remote(config_text)

    blocks: dict[str, str] = {}
    for m in _BLOCK_RE.finditer(config_text):
        blocks[m.group(1).lower()] = m.group(2).strip()
    if "ca" not in blocks or not blocks["ca"]:
        raise ValueError("missing <ca> block")

    auth_m = _AUTH_RE.search(config_text)
    auth = auth_m.group(1).upper() if auth_m else DEFAULT_AUTH
    cipher_m = _CIPHER_RE.search(config_text)
    data_ciphers = list(DEFAULT_DATA_CIPHERS)
    if cipher_m:
        cipher = cipher_m.group(1)
        data_ciphers = [cipher] + [c for c in data_ciphers if c.lower() != cipher.lower()]

    tls: dict = {
        "certificate": blocks["ca"],
        "certificate_profile": "legacy",
    }
    if blocks.get("cert"):
        tls["client_certificate"] = blocks["cert"]
    if blocks.get("key"):
        tls["client_key"] = blocks["key"]

    return {
        "type": "openvpn-client",
        "tag": tag,
        "server": server,
        "server_port": server_port,
        "network": "tcp",
        "username": username,
        "password": password,
        "tls": tls,
        "data_ciphers": data_ciphers,
        "data_ciphers_fallback": data_ciphers[0],
        "auth": auth,
        "system": False,
        "redirect_gateway": True,
    }


def build_singbox_config(endpoints: list[dict]) -> dict:
    """Wrap endpoints in a minimal checkable sing-box config."""
    tags = [ep["tag"] for ep in endpoints]
    return {
        "log": {"level": "info"},
        "endpoints": endpoints,
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": tags + ["direct"]},
            {"type": "urltest", "tag": "auto", "outbounds": tags, "interval": "5m", "tolerance": 300},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy", "auto_detect_interface": True},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert VPNGate .ovpn (TCP) to sing-box config")
    parser.add_argument("--input", required=True, help="input .ovpn file")
    parser.add_argument("--output", required=True, help="output sing-box JSON file")
    parser.add_argument("--tag", default="vpngate-0", help="endpoint tag")
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    args = parser.parse_args(argv)

    config_text = Path(args.input).read_text(encoding="utf-8")
    endpoint = ovpn_to_endpoint(config_text, tag=args.tag, username=args.username, password=args.password)
    Path(args.output).write_text(json.dumps(build_singbox_config([endpoint]), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output} with 1 endpoint ({endpoint['server']}:{endpoint['server_port']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
