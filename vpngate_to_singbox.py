"""Minimal VPNGate .ovpn -> sing-box openvpn-client converter (stdlib only)."""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import re
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
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


def probe_tcp_latency(host: str, port: int, timeout: int = 5) -> int:
    """Measure TCP handshake latency in ms; return 0 when unreachable.

    This is a real-connection pre-filter: VPNGate advertises Speed values
    that say nothing about whether the node accepts connections right now.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = None
    start = time.monotonic()
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return max(1, int((time.monotonic() - start) * 1000))
    except OSError:
        return 0
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("eof")
        data += chunk
    return data


def _socks5_get_latency_ms(proxy_host: str, proxy_port: int,
                           target_host: str = "www.gstatic.com",
                           target_port: int = 443,
                           path: str = "/generate_204",
                           timeout: float = 20) -> int | None:
    """One HTTPS GET through a SOCKS5 proxy; ms on HTTP 204, else None."""
    family = socket.AF_INET6 if ":" in proxy_host else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            return None
        try:
            addr = socket.inet_aton(target_host)
            request = b"\x05\x01\x00\x01" + addr + target_port.to_bytes(2, "big")
        except OSError:
            encoded = target_host.encode("idna")
            if len(encoded) > 255:
                return None
            request = (b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded
                       + target_port.to_bytes(2, "big"))
        sock.sendall(request)
        reply = _recv_exact(sock, 4)
        if reply[1] != 0:
            return None
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            return None
        start = time.monotonic()
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        head = b""
        while b"\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            head += chunk
            if len(head) > 8192:
                return None
        try:
            code = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return None
        if code != 204:
            return None
        return max(1, int((time.monotonic() - start) * 1000))
    except (OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def measure_real_latency(endpoint: dict, singbox_bin: str = "sing-box",
                         timeout: int = 90, poll_interval: int = 2,
                         target_host: str = "www.gstatic.com",
                         target_port: int = 443,
                         path: str = "/generate_204") -> int | None:
    """Dial one endpoint with a throwaway sing-box; end-to-end GET ms or None."""
    port = _free_port()
    probe_endpoint = dict(endpoint)
    probe_endpoint["tag"] = "dial-probe"
    config = build_singbox_config([probe_endpoint], mixed_listen="127.0.0.1",
                                  mixed_port=port)
    tmpdir = tempfile.TemporaryDirectory()
    try:
        cfg_path = str(Path(tmpdir.name) / "dial.json")
        Path(cfg_path).write_text(json.dumps(config), encoding="utf-8")
        try:
            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            return None
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                first = _socks5_get_latency_ms(
                    "127.0.0.1", port, target_host, target_port, path,
                    timeout=min(10, max(1, remaining)))
                if first is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return first
                    return _socks5_get_latency_ms(
                        "127.0.0.1", port, target_host, target_port, path,
                        timeout=min(30, max(1, remaining)))
                time.sleep(poll_interval)
            return None
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
    finally:
        tmpdir.cleanup()


def _safe_dial(dial_fn, node: dict) -> int | None:
    try:
        result = dial_fn(node)
    except Exception:
        return None
    return result if isinstance(result, int) and result > 0 else None


def _iter_tcp_candidates(csv_text, username=DEFAULT_USERNAME, password=DEFAULT_PASSWORD):
    """Yield (speed, country, country_short, untagged-endpoint) for TCP rows."""
    lines = [ln for ln in csv_text.splitlines() if ln and not ln.startswith("*")]
    if not lines:
        raise ValueError("empty snapshot")
    if lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or "OpenVPN_ConfigData_Base64" not in reader.fieldnames:
        raise ValueError("snapshot columns are incomplete")

    found = False
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
        found = True
        yield (speed, (row.get("CountryLong") or "").strip(),
               (row.get("CountryShort") or "").strip().upper(), endpoint)
    if not found:
        raise ValueError("snapshot contains no TCP-convertible nodes")


def snapshot_to_nodes(
    csv_text: str,
    limit: int | None = 0,
    probe: bool = True,
    probe_fn=None,
    probe_timeout: int = 5,
    probe_workers: int = 20,
    probe_pool: int = 30,
    real_topk: int = 0,
    dial_fn=None,
    dial_workers: int = 3,
    dial_timeout: int = 90,
    singbox_bin: str = "sing-box",
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
) -> list[dict]:
    """Parse a snapshot into node dicts with country + measured latency.

    Nodes are real-connection filtered (TCP handshake must succeed) and
    sorted by measured latency. With probe=False falls back to Speed ranking
    with latency_ms=None. limit=0/None means all nodes.

    With real_topk>0 the top-K handshake winners are additionally dialed
    through a real tunnel and re-ranked: measured nodes first by real
    end-to-end latency, the rest by handshake latency. Dial failures and
    exceptions keep the node as unmeasured instead of dropping it.
    Returns [] when nothing is reachable (caller decides failure).
    """
    candidates = list(_iter_tcp_candidates(csv_text, username, password))
    check = probe_fn if probe_fn is not None else (
        lambda host, port: probe_tcp_latency(host, port, probe_timeout))

    def _node(speed, country, country_short, endpoint, latency_ms):
        return {"server": endpoint["server"], "server_port": endpoint["server_port"],
                "country": country, "country_short": country_short,
                "speed": speed, "latency_ms": latency_ms, "real_latency_ms": None,
                "endpoint": endpoint}

    if not probe:
        ranked = sorted(candidates, key=lambda item: item[0], reverse=True)
        nodes = [_node(speed, country, short, ep, None)
                 for speed, country, short, ep in ranked]
    else:
        pool = sorted(candidates, key=lambda item: item[0], reverse=True)[:probe_pool]
        latencies: dict[int, int] = {}
        with ThreadPoolExecutor(max_workers=probe_workers) as executor:
            future_map = {executor.submit(check, ep["server"], ep["server_port"]): index
                          for index, (_, _, _, ep) in enumerate(pool)}
            for future in future_map:
                try:
                    latencies[future_map[future]] = future.result()
                except Exception:
                    latencies[future_map[future]] = 0

        alive = [(latencies[i], speed, country, short, ep)
                 for i, (speed, country, short, ep) in enumerate(pool)
                 if latencies.get(i, 0) > 0]
        alive.sort(key=lambda item: item[0])
        nodes = [_node(speed, country, short, ep, latency)
                 for latency, speed, country, short, ep in alive]

    if real_topk and real_topk > 0 and nodes:
        dial = dial_fn if dial_fn is not None else (
            lambda node: measure_real_latency(node["endpoint"], singbox_bin, dial_timeout))
        with ThreadPoolExecutor(max_workers=dial_workers) as executor:
            future_map = {executor.submit(_safe_dial, dial, node): node
                          for node in nodes[:real_topk]}
            for future in future_map:
                future_map[future]["real_latency_ms"] = future.result()
        nodes.sort(key=lambda n: (0, n["real_latency_ms"])
                   if n["real_latency_ms"] is not None
                   else (1, n["latency_ms"] if n["latency_ms"] is not None else 10 ** 9))

    if limit:
        nodes = nodes[:limit]
    return nodes


def nodes_to_endpoints(nodes: list[dict], tag_prefix: str = "vpngate") -> list[dict]:
    """Assign tags and return clean sing-box endpoint dicts (no metadata keys)."""
    endpoints = []
    for index, node in enumerate(nodes):
        endpoint = dict(node["endpoint"])
        endpoint["tag"] = f"{tag_prefix}-{index}"
        node["endpoint"] = endpoint
        endpoints.append(endpoint)
    return endpoints


def snapshot_to_endpoints(
    csv_text: str,
    limit: int | None = 0,
    tag_prefix: str = "vpngate",
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    probe: bool = True,
    probe_fn=None,
    probe_timeout: int = 5,
    probe_workers: int = 20,
    probe_pool: int = 30,
    real_topk: int = 0,
    dial_fn=None,
    dial_workers: int = 3,
    dial_timeout: int = 90,
    singbox_bin: str = "sing-box",
) -> list[dict]:
    """Parse a VPNGate CSV snapshot into tagged sing-box endpoints.

    Prefers nodes with a working TCP handshake, ranked by measured latency.
    With real_topk>0 the top-K are re-ranked by real tunnel latency.
    limit=0/None means all nodes.
    """
    nodes = snapshot_to_nodes(
        csv_text, limit=limit, probe=probe, probe_fn=probe_fn,
        probe_timeout=probe_timeout, probe_workers=probe_workers,
        probe_pool=probe_pool, real_topk=real_topk, dial_fn=dial_fn,
        dial_workers=dial_workers, dial_timeout=dial_timeout,
        singbox_bin=singbox_bin, username=username, password=password)
    if not nodes:
        raise ValueError("snapshot contains no reachable nodes")
    return nodes_to_endpoints(nodes, tag_prefix)


def build_singbox_config(
    endpoints: list[dict],
    mixed_listen: str | None = None,
    mixed_port: int | None = None,
    mixed_users: list[tuple[str, str]] | None = None,
    final: str = "auto",
) -> dict:
    """Wrap endpoints in a minimal checkable sing-box config.

    route.final defaults to the "auto" urltest group so traffic fails over
    across healthy nodes automatically; pass an endpoint tag to pin one.
    The urltest group always contains "direct" as a last-resort outlet so
    a total VPNGate outage degrades to direct instead of blackholing.
    """
    tags = [ep["tag"] for ep in endpoints]
    config: dict = {
        "log": {"level": "info"},
        "endpoints": endpoints,
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": tags + ["direct"]},
            {"type": "urltest", "tag": "auto", "outbounds": tags + ["direct"],
             "interval": "1m", "tolerance": 800},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": final, "auto_detect_interface": True},
    }
    if mixed_listen is not None and mixed_port is not None:
        inbound: dict = {"type": "mixed", "tag": "mixed-in",
                         "listen": mixed_listen, "listen_port": mixed_port}
        if mixed_users:
            inbound["users"] = [{"username": user, "password": password}
                                for user, password in mixed_users]
        config["inbounds"] = [inbound]
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert VPNGate .ovpn (TCP) to sing-box config")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="input .ovpn file")
    group.add_argument("--csv", help="input VPNGate snapshot CSV file")
    parser.add_argument("--output", required=True, help="output sing-box JSON file")
    parser.add_argument("--tag", default="vpngate-0", help="endpoint tag (--input) or prefix (--csv)")
    parser.add_argument("--limit", type=int, default=0,
                        help="max endpoints for --csv mode, 0 = all")
    parser.add_argument("--real-topk", type=int, default=0,
                        help="re-rank top-K by real tunnel latency (0 = off)")
    parser.add_argument("--no-probe", action="store_true",
                        help="skip TCP handshake probing, rank by Speed instead")
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
            probe=not args.no_probe, real_topk=args.real_topk,
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
