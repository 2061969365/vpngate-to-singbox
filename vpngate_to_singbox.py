"""Minimal VPNGate .ovpn -> sing-box openvpn-client converter (stdlib only)."""
from __future__ import annotations

import argparse
import base64
import csv
import io
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


def snapshot_to_endpoints(
    csv_text: str,
    limit: int = 8,
    tag_prefix: str = "vpngate",
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
) -> list[dict]:
    """Parse a VPNGate CSV snapshot, keep TCP-convertible rows, rank by Speed desc."""
    lines = [ln for ln in csv_text.splitlines() if ln and not ln.startswith("*")]
    if not lines:
        raise ValueError("empty snapshot")
    if lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or "OpenVPN_ConfigData_Base64" not in reader.fieldnames:
        raise ValueError("snapshot columns are incomplete")

    candidates: list[tuple[int, dict]] = []
    for row in reader:
        encoded = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not encoded:
            continue
        try:
            config_text = base64.b64decode(encoded, validate=True).decode("utf-8")
            endpoint = ovpn_to_endpoint(config_text, tag="", username=username, password=password)
        except (ValueError, UnicodeError):
            continue  # UDP-only / broken / unsafe rows are skipped
        try:
            speed = int((row.get("Speed") or "0").strip() or "0")
        except ValueError:
            speed = 0
        candidates.append((speed, endpoint))

    if not candidates:
        raise ValueError("snapshot contains no TCP-convertible nodes")
    candidates.sort(key=lambda item: item[0], reverse=True)
    endpoints = []
    for index, (_, endpoint) in enumerate(candidates[:limit]):
        endpoint["tag"] = f"{tag_prefix}-{index}"
        endpoints.append(endpoint)
    return endpoints


def build_singbox_config(
    endpoints: list[dict],
    mixed_listen: str | None = None,
    mixed_port: int | None = None,
) -> dict:
    """Wrap endpoints in a minimal checkable sing-box config."""
    tags = [ep["tag"] for ep in endpoints]
    config: dict = {
        "log": {"level": "info"},
        "endpoints": endpoints,
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": tags + ["direct"]},
            {"type": "urltest", "tag": "auto", "outbounds": tags, "interval": "5m", "tolerance": 300},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy", "auto_detect_interface": True},
    }
    if mixed_listen is not None and mixed_port is not None:
        config["inbounds"] = [
            {"type": "mixed", "tag": "mixed-in", "listen": mixed_listen, "listen_port": mixed_port},
        ]
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert VPNGate .ovpn (TCP) to sing-box config")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="input .ovpn file")
    group.add_argument("--csv", help="input VPNGate snapshot CSV file")
    parser.add_argument("--output", required=True, help="output sing-box JSON file")
    parser.add_argument("--tag", default="vpngate-0", help="endpoint tag (--input) or prefix (--csv)")
    parser.add_argument("--limit", type=int, default=8, help="max endpoints for --csv mode")
    parser.add_argument("--mixed", default=None, help="optional mixed inbound HOST:PORT for dial tests")
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    args = parser.parse_args(argv)

    mixed_listen: str | None = None
    mixed_port: int | None = None
    if args.mixed:
        mixed_listen, _, mixed_port_str = args.mixed.rpartition(":")
        mixed_port = int(mixed_port_str)

    if args.csv:
        csv_text = Path(args.csv).read_text(encoding="utf-8")
        endpoints = snapshot_to_endpoints(
            csv_text, limit=args.limit, tag_prefix=args.tag,
            username=args.username, password=args.password,
        )
        Path(args.output).write_text(
            json.dumps(build_singbox_config(endpoints, mixed_listen, mixed_port), indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.output} with {len(endpoints)} endpoints")
        return 0

    config_text = Path(args.input).read_text(encoding="utf-8")
    endpoint = ovpn_to_endpoint(config_text, tag=args.tag, username=args.username, password=args.password)
    Path(args.output).write_text(
        json.dumps(build_singbox_config([endpoint], mixed_listen, mixed_port), indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output} with 1 endpoint ({endpoint['server']}:{endpoint['server_port']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
