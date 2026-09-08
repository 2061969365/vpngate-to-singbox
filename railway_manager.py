"""Railway entrypoint: single-$PORT multiplexer + sing-box supervisor (stdlib only).

Railway exposes exactly one ingress port ($PORT, HTTP) plus an optional raw
TCP Proxy. This process owns $PORT and dispatches by first bytes:

  0x05...          -> SOCKS5 handshake, piped to sing-box mixed inbound
  CONNECT ...      -> HTTP proxy request, piped to sing-box mixed inbound
  GET/POST/...     -> plain HTTP: /healthz (open), /ui shell, /api/* (authed)
  anything else    -> closed

Security model: /healthz is open for the platform healthcheck. Everything
else that serves data or mutates state (/api/*) requires
``Authorization: Bearer <ADMIN_TOKEN>``. The /ui shell itself carries no
data (it fetches /api/status with a token the operator pastes once).

Outbound traffic leaves through sing-box openvpn-client endpoints
(system:false, internal stack, no TUN / no NET_ADMIN needed).
"""
from __future__ import annotations

import json
import os
import random
import secrets
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from vpngate_to_singbox import (
    build_singbox_config,
    measure_real_latency,
    nodes_to_endpoints,
    primary_server,
    probe_tcp_latency,
    snapshot_to_nodes,
)

DEFAULT_SNAPSHOT_URL = "https://www.vpngate.net/api/iphone/"
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                b"OPTIONS ", b"PATCH ")
MIN_PROXY_PASS_LEN = 16
MIN_ADMIN_TOKEN_LEN = 16
HEALTH_CHECK_INTERVAL = 60
PINNED_FAIL_THRESHOLD = 3
SUPERVISE_INTERVAL = 10
# Cold start uses a bounded Speed-ranked chunk so the first config lands in
# seconds and /healthz goes 200 fast; periodic refreshes scan everything.
INITIAL_PROBE_POOL = 30
CRASH_BACKOFFS = (5, 10, 20, 40, 300)
MAX_CRASH_STREAK = 5

UI_HTML = """\
<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vpngate console</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
#topnav{display:flex;align-items:center;gap:26px;padding:16px 32px;font-size:14px}
#topnav .logo{font-weight:700;font-size:16px}
#topnav .links{display:flex;gap:22px;color:#ccc}
#topnav .right{margin-left:auto;display:flex;gap:14px;align-items:center}
#topnav input{background:#111;border:1px solid #444;color:#fff;border-radius:6px;padding:6px 10px;font-size:13px}
#topnav .cta{border:1px solid #555;border-radius:999px;padding:7px 18px;cursor:pointer}
.hero{padding:70px 32px 56px;background:radial-gradient(ellipse 60% 50% at 70% 40%,rgba(64,120,255,.22),transparent 70%),radial-gradient(ellipse 40% 40% at 30% 70%,rgba(0,200,150,.12),transparent 70%),#000}
#hero-kicker{font-size:56px;font-weight:700;letter-spacing:-.03em;line-height:1.05}
#hero-sub{color:#b5b5b5;font-size:15px;line-height:1.65;max-width:760px;margin-top:14px}
#pills{display:flex;gap:10px;margin-top:20px;flex-wrap:wrap}
#pills span{border:1px solid #444;border-radius:999px;padding:7px 18px;font-size:13px;color:#ddd;cursor:pointer}
#pills span.on{background:#fff;color:#000;border-color:#fff}
.actions{display:flex;gap:12px;margin-top:20px}
#btn-verify{background:#fff;color:#000;border-radius:999px;padding:10px 26px;font-size:14px;font-weight:600;cursor:pointer;border:none}
#btn-refresh{border:1px solid #555;border-radius:999px;padding:10px 26px;font-size:14px;color:#fff;background:transparent;cursor:pointer}
#btn-fullprobe{border:1px solid #8ab4ff;border-radius:999px;padding:10px 26px;font-size:14px;color:#8ab4ff;background:transparent;cursor:pointer}
.section{padding:44px 32px;border-top:1px solid #1c1c1c;max-width:1200px}
.section h2{font-size:26px;font-weight:600;margin-bottom:12px}
.section p{color:#b5b5b5;font-size:14px;line-height:1.7;max-width:800px;margin-bottom:16px}
table.bench{width:100%;border-collapse:collapse;font-size:14px}
table.bench th,table.bench td{text-align:left;padding:10px 14px;border-bottom:1px solid #222}
table.bench th{color:#888;font-weight:500}
table.bench td.hl{color:#fff;font-weight:600}
table.bench td.op a{color:#8ab4ff;cursor:pointer;text-decoration:none}
#history-line{color:#888;font-size:13px;margin-top:16px}
.footer{border-top:1px solid #1c1c1c;padding:28px 32px;display:flex;gap:48px;color:#888;font-size:13px}
.footer b{color:#ccc;display:block;margin-bottom:8px}
@media(max-width:768px){#hero-kicker{font-size:36px}.hero,.section{padding-left:18px;padding-right:18px}#topnav .links{display:none}}
</style></head>
<body>
<div id="topnav"><span class="logo">vpngate</span><span class="links"><span>总览</span><span>节点</span><span>历史</span></span><span class="right"><input id="token" type="password" size="18" placeholder="ADMIN_TOKEN"><span class="cta" onclick="saveToken()">Save</span></span></div>
<div class="hero">
<div id="hero-kicker">—<br>—</div>
<p id="hero-sub">loading…</p>
<div id="pills"></div>
<div class="actions"><button id="btn-verify" onclick="verifyNow()">验证出口 IP</button><button id="btn-refresh" onclick="refreshNow()">刷新节点</button><button id="btn-fullprobe" onclick="fullProbeNow()">全量真测</button></div>
</div>
<div class="section">
<h2>可用节点</h2>
<p>按隧道延迟排序。Speed 排名不等于可拨通，首选由 urltest 实测决定，多 endpoint 兜底。</p>
<table class="bench"><thead><tr><th>Endpoint</th><th>国家</th><th>握手</th><th>实测</th><th>存活</th><th>操作</th></tr></thead><tbody id="bench-body"></tbody></table>
<p id="history-line"></p>
</div>
<div class="footer"><div><b>控制台</b><div>总览 · 节点 · 历史</div></div><div><b>状态</b><div id="foot-status">—</div></div><div><b>说明</b><div>自用调试 · sing-box 内部协议栈 · 无 TUN</div></div></div>
<script>
var activeCountry = "";
function authHeaders() {
  return {"Authorization": "Bearer " + (localStorage.getItem("admin_token") || "")};
}
function saveToken() {
  localStorage.setItem("admin_token", document.getElementById("token").value);
  refresh();
}
async function api(path, method, body) {
  const r = await fetch(path, {method: method || "GET", headers: authHeaders(),
    body: body ? JSON.stringify(body) : undefined});
  if (r.status === 401) throw new Error("unauthorized: save ADMIN_TOKEN first");
  return r.json();
}
function fmtMs(v) { return v == null ? "—" : v + "ms"; }
async function refresh() {
  try {
    const s = await api("/api/status");
    const eps = s.endpoints.filter(e => !activeCountry || e.country_short === activeCountry);
    const pref = s.endpoints.find(e => e.tag === s.preferred_tag) || eps[0];
    document.getElementById("hero-kicker").innerHTML =
      (pref ? pref.country_short + "<br>" + fmtMs(pref.real_latency_ms != null ? pref.real_latency_ms : pref.latency_ms) : "—<br>无节点");
    document.getElementById("hero-sub").textContent =
      pref ? ("经 " + pref.tag + " 出站 · " + pref.server + ":" + pref.server_port + " · 存活 " + (pref.alive_seconds || 0) + "s") : "暂无可用节点";
    document.getElementById("pills").innerHTML =
      '<span data-c="" class="' + (activeCountry === "" ? "on" : "") + '">全部 ' + s.endpoints.length + "</span>" +
      s.countries.map(c => '<span data-c="' + c.code + '" class="' + (activeCountry === c.code ? "on" : "") + '">' + c.name + "</span>").join("");
    document.querySelectorAll("#pills span").forEach(el => el.onclick = () => { activeCountry = el.getAttribute("data-c"); refresh(); });
    document.getElementById("bench-body").innerHTML = eps.map(e =>
      "<tr><td class='hl'>" + e.tag + (e.tag === s.preferred_tag ? " *pinned" : "") + "</td><td>" + e.country_short + "</td><td class='hl'>" + fmtMs(e.latency_ms) +
      "</td><td class='hl'>" + fmtMs(e.real_latency_ms) + "</td><td>" + (e.alive_seconds || 0) + "s</td>" +
      "<td class='op'><a onclick='probeOne(" + e.tag + ")'>测速</a> <a onclick='switchTag(" + e.tag + ")'>切换</a></td></tr>").join("");
    document.getElementById("history-line").textContent =
      "refresh ok/fail: " + s.refresh_ok + "/" + s.refresh_fail + " · uptime: " + s.uptime_seconds + "s · error: " + s.last_error +
      (s.full_probe && s.full_probe.state !== "idle" ? " · 全量真测: " + s.full_probe.state + " " + s.full_probe.done + "/" + s.full_probe.total : "");
    document.getElementById("foot-status").textContent = "uptime " + s.uptime_seconds + "s · refresh " + s.refresh_ok + "/" + s.refresh_fail;
  } catch (e) {
    document.getElementById("hero-sub").textContent = "status fetch failed: " + e;
  }
}
async function switchTag(tag) {
  await api("/api/switch", "POST", {"tag": tag});
  refresh();
}
async function probeOne(tag) {
  await api("/api/switch", "POST", {"tag": tag});
  refresh();
}
async function refreshNow() {
  await api("/api/refresh", "POST", {});
  refresh();
}
async function fullProbeNow() {
  await api("/api/full_probe", "POST", {});
  refresh();
}
async function verifyNow() {
  await refresh();
  document.getElementById("hero-sub").textContent += " · 已重新验证";
}
document.getElementById("token").value = localStorage.getItem("admin_token") || "";
refresh();
setInterval(refresh, 10000);
</script>
</body></html>
"""


def classify_first_bytes(data: bytes) -> str:
    """Decide what a new connection is from its first bytes (peeked, not consumed)."""
    if not data:
        return "unknown"
    if data[0] == 0x05:
        return "socks5"
    if data.startswith(b"CONNECT "):
        return "http-connect"
    if data.startswith(HTTP_METHODS):
        return "http"
    return "unknown"


def default_fetch(url: str, timeout: int = 20) -> str:
    """Fetch a snapshot over HTTPS only (plain HTTP allows MITM node injection)."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError(f"refusing non-https snapshot url: {url}")
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def build_config_from_env(env: dict) -> dict:
    """Validate deployment env. Exits nonzero on weak credentials or plain-http."""
    password = env.get("PROXY_PASS", "p")
    if len(password) < MIN_PROXY_PASS_LEN:
        print(f"refusing to start: PROXY_PASS must be at least {MIN_PROXY_PASS_LEN} chars",
              flush=True)
        raise SystemExit(2)
    snapshot_url = env.get("SNAPSHOT_URL", DEFAULT_SNAPSHOT_URL)
    if urllib.parse.urlsplit(snapshot_url).scheme != "https":
        print("refusing to start: SNAPSHOT_URL must be https", flush=True)
        raise SystemExit(2)
    admin_token = env.get("ADMIN_TOKEN", "")
    generated = False
    if len(admin_token) < MIN_ADMIN_TOKEN_LEN:
        admin_token = secrets.token_urlsafe(24)
        generated = True
    return {
        "port": int(env.get("PORT", "8080")),
        "mixed_port": int(env.get("MIXED_PORT", "40000")),
        "username": env.get("PROXY_USER", "u"),
        "password": password,
        "admin_token": admin_token,
        "admin_token_generated": generated,
        "snapshot_url": snapshot_url,
        "refresh_seconds": int(env.get("REFRESH_SECONDS", "1200")),
        "limit": int(env.get("LIMIT", "0")),
        "real_topk": int(env.get("REAL_TOPK", "30")),
        "data_dir": env.get("DATA_DIR", "."),
        "vless_uuid": env.get("VLESS_UUID", ""),
        "vless_direct_port": int(env.get("VLESS_DIRECT_PORT", "8080")),
        "vless_chain_port": int(env.get("VLESS_CHAIN_PORT", "8082")),
        "tunnel_token": env.get("TUNNEL_TOKEN", ""),
        "cloudflared_bin": env.get("CLOUDFLARED_BIN", "cloudflared"),
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _http_response(status: str, content_type: str, body: bytes) -> bytes:
    header = (f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n"
              f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return header.encode() + body


def _forward(source: socket.socket, dest: socket.socket) -> int:
    """Forward until EOF, returning bytes moved."""
    moved = 0
    try:
        while True:
            chunk = source.recv(65536)
            if not chunk:
                break
            dest.sendall(chunk)
            moved += len(chunk)
    except OSError:
        pass
    return moved


def _write_private_json(path: str, obj: dict) -> None:
    """Atomically write JSON and restrict to owner-only (holds credentials)."""
    tmp_path = f"{path}.tmp-{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=2)
        handle.write("\n")
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass
    os.replace(tmp_path, path)


class RailwayManager:
    def __init__(
        self,
        port: int = 8080,
        mixed_port: int = 40000,
        username: str = "u",
        password: str = "p",
        admin_token: str | None = None,
        snapshot_url: str = DEFAULT_SNAPSHOT_URL,
        refresh_seconds: int = 1200,
        limit: int | None = 0,
        real_topk: int = 0,
        dial_fn=None,
        vless_uuid: str = "",
        vless_direct_port: int = 8080,
        vless_chain_port: int = 8082,
        tunnel_token: str = "",
        cloudflared_bin: str = "cloudflared",
        config_path: str = "singbox-railway.json",
        nodes_path: str = "nodes.json",
        state_path: str = "state.json",
        singbox_bin: str = "sing-box",
        start_singbox: bool = True,
        auto_refresh: bool = True,
        fetch_on_start: bool = True,
        retry_delays: tuple = (5, 10),
        fetcher=None,
    ) -> None:
        self.port = port
        self.mixed_port = mixed_port
        self.username = username
        self.password = password
        self.admin_token = admin_token
        self.snapshot_url = snapshot_url
        self.refresh_seconds = refresh_seconds
        self.limit = limit
        self.real_topk = real_topk
        self.dial_fn = (dial_fn if dial_fn is not None else
                        (lambda node: measure_real_latency(
                            node["endpoint"], self.singbox_bin)))
        self.config_path = config_path
        self.nodes_path = nodes_path
        self.state_path = state_path
        self.last_good_path = f"{config_path}.last-good"
        self.singbox_bin = singbox_bin
        self.want_singbox = start_singbox
        self.auto_refresh = auto_refresh
        self.fetch_on_start = fetch_on_start
        self.retry_delays = retry_delays
        self.fetcher = fetcher or default_fetch
        self.vless_uuid = vless_uuid
        self.vless_direct_port = vless_direct_port
        self.vless_chain_port = vless_chain_port
        self.tunnel_token = tunnel_token
        self.cloudflared_bin = cloudflared_bin
        self._cloudflared_proc: subprocess.Popen | None = None
        self.preferred_tag: str | None = None
        self._nodes: list[dict] = []
        self._first_seen: dict[str, str] = {}
        self._fail_streak = 0
        self._pinned_fail_streak = 0
        self._crash_streak = 0
        self._retry_after = 0.0
        self._lock = threading.RLock()
        self.status: dict = {
            "endpoints": [],
            "countries": [],
            "preferred_tag": None,
            "refresh_history": [],
            "refresh_ok": 0,
            "refresh_fail": 0,
            "last_refresh": None,
            "last_error": None,
            "started_at": None,
            "proxy": f"127.0.0.1:{mixed_port}",
            "traffic": {"connections": 0, "bytes_up": 0, "bytes_down": 0},
            "full_probe": {"state": "idle", "done": 0, "total": 0},
            "tunnel": {"state": "off"},
        }
        self._full_probe_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._listener: socket.socket | None = None
        self._singbox_proc: subprocess.Popen | None = None
        self._stderr_handle = None
        self.bound_port = port

    # -- lifecycle ------------------------------------------------------
    def start(self) -> int:
        # Bind first so $PORT (and /healthz) answers immediately; the first
        # snapshot refresh — which may dial several tunnels — runs behind.
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("0.0.0.0", self.port))
        self._listener.listen(128)
        self._listener.settimeout(1.0)
        self.bound_port = self._listener.getsockname()[1]
        self.status["started_at"] = _now_iso()
        threading.Thread(target=self._accept_loop, daemon=True).start()
        if self.auto_refresh:
            threading.Thread(target=self._refresh_loop, daemon=True).start()
        threading.Thread(target=self._supervise_loop, daemon=True).start()
        threading.Thread(target=self._health_monitor_loop, daemon=True).start()
        if self.fetch_on_start:
            threading.Thread(target=self._initial_refresh, daemon=True).start()
        self._start_cloudflared()
        print(f"listening on 0.0.0.0:{self.bound_port}, backend 127.0.0.1:{self.mixed_port}",
              flush=True)
        return self.bound_port

    def _initial_refresh(self) -> None:
        # Fast path first: serve the last-good config within seconds so
        # /healthz goes 200 before the (minutes-long) first live refresh
        # finishes. Without this the deploy healthcheck only sees 503.
        if self._boot_from_last_good():
            self.refresh_once()
        elif not self.refresh_once(probe_pool=INITIAL_PROBE_POOL):
            self._boot_from_last_good()

    def stop(self) -> None:
        self._stop_event.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        self._terminate_singbox()
        self._terminate_cloudflared()

    # -- accept / dispatch ----------------------------------------------
    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop_event.is_set():
            try:
                client, _ = self._listener.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _handle_client(self, client: socket.socket) -> None:
        try:
            client.settimeout(10)
            peek = client.recv(4096)
            if not peek:
                return
            kind = classify_first_bytes(peek)
            if kind in ("socks5", "http-connect"):
                with self._lock:
                    self.status["traffic"]["connections"] += 1
                self._pipe_to_backend(client, peek)
            elif kind == "http":
                self._handle_http(client, peek)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _authorized(self, headers: dict) -> bool:
        if not self.admin_token:
            return True
        return headers.get("authorization", "") == f"Bearer {self.admin_token}"

    @staticmethod
    def _parse_request(data: bytes):
        try:
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()
            return method.upper(), path.split("?", 1)[0], headers, body
        except (ValueError, IndexError):
            return None

    def _handle_http(self, client: socket.socket, peek: bytes) -> None:
        data = peek
        while b"\r\n\r\n" not in data and len(data) < 65536:
            try:
                chunk = client.recv(4096)
            except OSError:
                return
            if not chunk:
                break
            data += chunk
        parsed = self._parse_request(data)
        if parsed is None:
            return
        method, path, headers, body = parsed
        if path == "/healthz" and method == "GET":
            if self._healthy():
                client.sendall(_http_response("200 OK", "text/plain", b"ok"))
            else:
                client.sendall(_http_response("503 Service Unavailable",
                                              "text/plain", b"not ready"))
            return
        if path in ("/", "/ui") and method == "GET":
            client.sendall(_http_response("200 OK", "text/html; charset=utf-8",
                                          UI_HTML.encode()))
            return
        if not self._authorized(headers):
            client.sendall(_http_response("401 Unauthorized", "text/plain",
                                          b"missing or invalid admin token"))
            return
        if path == "/api/status" and method == "GET":
            client.sendall(_http_response("200 OK", "application/json",
                                          json.dumps(self.status_snapshot()).encode()))
        elif path == "/api/refresh" and method == "POST":
            ok = self.refresh_once()
            client.sendall(_http_response(
                "200 OK", "application/json", json.dumps({"ok": ok}).encode()))
        elif path == "/api/full_probe" and method == "POST":
            self._start_full_probe()
            client.sendall(_http_response(
                "202 Accepted", "application/json",
                json.dumps({"accepted": True}).encode()))
        elif path == "/api/switch" and method == "POST":
            try:
                payload = json.loads((body or b"{}").decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                payload = None
            if not isinstance(payload, dict):
                client.sendall(_http_response("400 Bad Request", "text/plain",
                                              b"invalid json"))
                return
            ok, detail = self.switch(tag=payload.get("tag"), country=payload.get("country"))
            status = "200 OK" if ok else "400 Bad Request"
            client.sendall(_http_response(
                status, "application/json",
                json.dumps({"ok": ok, "preferred_tag": self.preferred_tag,
                            "detail": detail}).encode()))
        elif path.startswith("/api/"):
            client.sendall(_http_response("405 Method Not Allowed", "text/plain",
                                          b"method not allowed"))
        else:
            client.sendall(_http_response("404 Not Found", "text/plain", b"not found"))

    def _healthy(self) -> bool:
        with self._lock:
            if not self.status["endpoints"]:
                return False
            if not self.want_singbox:
                return True
            proc = self._singbox_proc
            return proc is not None and proc.poll() is None

    def _pipe_to_backend(self, client: socket.socket, peek: bytes) -> None:
        try:
            backend = socket.create_connection(("127.0.0.1", self.mixed_port), timeout=10)
        except OSError:
            return
        try:
            backend.sendall(peek)
            up = [0]
            down = [0]

            def _up() -> None:
                up[0] = _forward(client, backend)

            def _down() -> None:
                down[0] = _forward(backend, client)

            first = threading.Thread(target=_up, daemon=True)
            second = threading.Thread(target=_down, daemon=True)
            first.start()
            second.start()
            first.join()
            second.join()
            with self._lock:
                self.status["traffic"]["bytes_up"] += up[0] + len(peek)
                self.status["traffic"]["bytes_down"] += down[0]
        except OSError:
            pass
        finally:
            try:
                backend.close()
            except OSError:
                pass

    # -- status / persistence --------------------------------------------
    def status_snapshot(self) -> dict:
        with self._lock:
            snapshot = json.loads(json.dumps(self.status))
        now = datetime.now(timezone.utc)
        try:
            started = datetime.strptime(self.status["started_at"] or "", "%Y-%m-%dT%H:%M:%SZ")
            started = started.replace(tzinfo=timezone.utc)
            snapshot["uptime_seconds"] = max(0, int((now - started).total_seconds()))
        except (ValueError, TypeError):
            snapshot["uptime_seconds"] = 0
        for ep in snapshot["endpoints"]:
            host, port = primary_server(ep)
            first = self._first_seen.get(f"{host}:{port}")
            ep["first_seen"] = first
            try:
                seen = datetime.strptime(first or "", "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc)
                ep["alive_seconds"] = max(0, int((now - seen).total_seconds()))
            except (ValueError, TypeError):
                ep["alive_seconds"] = 0
        return snapshot

    def _record_history(self, event: str, detail: str = "") -> None:
        with self._lock:
            self.status["refresh_history"].append(
                {"ts": _now_iso(), "event": event, "detail": detail})
            del self.status["refresh_history"][:-20]

    def _persist_state(self) -> None:
        _write_private_json(self.state_path, {"preferred_tag": self.preferred_tag})

    def _persist_nodes(self) -> None:
        _write_private_json(self.nodes_path,
                            {"nodes": self._nodes, "first_seen": self._first_seen})

    def load_persisted(self) -> tuple[list, str | None]:
        nodes: list = []
        first_seen: dict = {}
        try:
            with open(self.nodes_path, encoding="utf-8") as handle:
                saved = json.load(handle)
            nodes = saved.get("nodes", [])
            first_seen = saved.get("first_seen", {})
        except (OSError, ValueError):
            pass
        preferred: str | None = None
        try:
            with open(self.state_path, encoding="utf-8") as handle:
                preferred = json.load(handle).get("preferred_tag")
        except (OSError, ValueError):
            pass
        with self._lock:
            self._nodes = nodes
            self._first_seen = first_seen
            self.preferred_tag = preferred
        return nodes, preferred

    def _boot_from_last_good(self) -> bool:
        try:
            with open(self.last_good_path, "rb") as src:
                payload = src.read()
            if not payload:
                return False
            json.loads(payload.decode("utf-8"))
        except (OSError, ValueError):
            return False
        tmp_path = f"{self.config_path}.tmp-{os.getpid()}"
        with open(tmp_path, "wb") as handle:
            handle.write(payload)
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, self.config_path)
        nodes, preferred = self.load_persisted()
        endpoints = nodes_to_endpoints(nodes) if nodes else []
        with self._lock:
            self.status["endpoints"] = [
                {"tag": ep["tag"], "server": primary_server(ep)[0],
                 "server_port": primary_server(ep)[1],
                 "country": n.get("country", ""), "country_short": n.get("country_short", ""),
                 "latency_ms": n.get("latency_ms"), "real_latency_ms": n.get("real_latency_ms"),
                 "speed": n.get("speed", 0)}
                for ep, n in zip(endpoints, nodes)]
            self.status["countries"] = self._countries()
            if preferred and preferred not in {ep["tag"] for ep in endpoints}:
                self.preferred_tag = None
                self._persist_state()
            self.status["last_error"] = "booted from last-good config (refresh failed)"
        if self.want_singbox:
            self._restart_singbox()
        self._record_history("boot-from-last-good", f"{len(endpoints)} endpoints")
        return True

    def _countries(self) -> list[dict]:
        seen: dict[str, str] = {}
        for node in self._nodes:
            code = node.get("country_short", "")
            if code and code not in seen:
                seen[code] = node.get("country", "")
        return [{"code": code, "name": seen[code]} for code in sorted(seen)]

    # -- snapshot refresh / sing-box supervision -------------------------
    def _effective_interval(self) -> int:
        if self._fail_streak >= 3:
            return max(300, self.refresh_seconds // 2)
        return self.refresh_seconds

    def _refresh_loop(self) -> None:
        next_run = time.monotonic() + self._effective_interval() + random.uniform(-30, 30)
        while not self._stop_event.wait(max(0.0, next_run - time.monotonic())):
            self.refresh_once()
            next_run = (time.monotonic() + self._effective_interval()
                        + random.uniform(-30, 30))

    def _supervise_loop(self) -> None:
        while not self._stop_event.wait(SUPERVISE_INTERVAL):
            with self._lock:
                if not self.want_singbox:
                    continue
                proc = self._singbox_proc
                if proc is not None and proc.poll() is None:
                    self._crash_streak = 0
                    continue
                if proc is None and not os.path.exists(self.config_path):
                    continue
                now = time.monotonic()
                if self._crash_streak >= MAX_CRASH_STREAK:
                    continue  # wait for next successful refresh to reset
                if now < self._retry_after:
                    continue
                delay = CRASH_BACKOFFS[min(self._crash_streak, len(CRASH_BACKOFFS) - 1)]
                self._retry_after = now + delay
                self._crash_streak += 1
                exit_info = f" (previous exit code {proc.poll()})" if proc else ""
                self.status["last_error"] = f"sing-box not running{exit_info}, restart in {delay}s"
                restart_now = now >= self._retry_after - delay
            if restart_now:
                self._restart_singbox()
            # Relaunch the tunnel if it was wanted but died; _start_cloudflared
            # soft-skips again when there is no token/binary.
            with self._lock:
                cf = self._cloudflared_proc
                want_cf = bool(self.tunnel_token)
                cf_alive = cf is not None and cf.poll() is None
            if want_cf and not cf_alive:
                self._start_cloudflared()

    def _health_monitor_loop(self) -> None:
        while not self._stop_event.wait(HEALTH_CHECK_INTERVAL):
            try:
                self.check_pinned_health()
            except Exception as exc:  # never kill the monitor thread
                print(f"health monitor error: {type(exc).__name__}: {exc}", flush=True)

    def check_pinned_health(self, probe_fn=None) -> str:
        """Probe the pinned endpoint; auto-unpin to urltest after 3 straight failures."""
        with self._lock:
            tag = self.preferred_tag
            node = next((n for n in self._nodes
                         if n.get("endpoint", {}).get("tag") == tag), None) if tag else None
        if tag is None or node is None:
            return "no-preferred"
        check = probe_fn if probe_fn is not None else probe_tcp_latency
        try:
            latency = check(node["server"], node["server_port"], 5)
        except Exception:
            latency = 0
        with self._lock:
            if latency > 0:
                self._pinned_fail_streak = 0
                return "pinned"
            self._pinned_fail_streak += 1
            if self._pinned_fail_streak < PINNED_FAIL_THRESHOLD:
                return "pinned"
            self.preferred_tag = None
            self._pinned_fail_streak = 0
            self.status["preferred_tag"] = None
            self._persist_state()
        self._apply_config(final="auto")
        self._record_history("auto-unpin",
                             f"{tag} failed {PINNED_FAIL_THRESHOLD}x, fell back to auto")
        return "unpinned"

    def switch(self, tag: str | None = None, country: str | None = None) -> tuple[bool, str]:
        with self._lock:
            if not self._nodes:
                return False, "no nodes loaded"
            node = None
            if country:
                wanted = country.strip().upper()
                candidates = [n for n in self._nodes
                              if n.get("country_short", "").upper() == wanted
                              or wanted in n.get("country", "").upper()]
                if not candidates:
                    return False, f"no nodes for country {country}"
                candidates.sort(key=lambda n: (
                    (0, n["real_latency_ms"])
                    if n.get("real_latency_ms") is not None
                    else (1, n.get("latency_ms")
                          if n.get("latency_ms") is not None else 10 ** 9),
                    -(n.get("speed") or 0)))
                node = candidates[0]
            elif tag in (None, "", "auto"):
                target: str | None = None
            else:
                node = next((n for n in self._nodes
                             if n.get("endpoint", {}).get("tag") == tag), None)
                if node is None:
                    return False, f"unknown tag {tag}"
            target = node["endpoint"]["tag"] if node is not None else None
            final = target or "auto"
        # Apply first; only commit in-memory state after the checked config lands.
        if not self._apply_config(final=final):
            return False, "config check failed, kept previous"
        with self._lock:
            self.preferred_tag = target
            self.status["preferred_tag"] = target
            self._persist_state()
        self._pinned_fail_streak = 0
        self._record_history("switch", f"final={final}")
        return True, final

    def _apply_config(self, final: str) -> bool:
        """Write checked config atomically and restart sing-box. Returns success."""
        with self._lock:
            endpoints = [n["endpoint"] for n in self._nodes]
            config = build_singbox_config(
                endpoints, "127.0.0.1", self.mixed_port,
                mixed_users=[(self.username, self.password)], final=final,
                vless_uuid=self.vless_uuid or None,
                vless_direct_port=self.vless_direct_port,
                vless_chain_port=self.vless_chain_port)
            tmp_path = f"{self.config_path}.tmp-{os.getpid()}"
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(config, handle, indent=2)
                handle.write("\n")
            if not self._check_config(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                return False
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            os.replace(tmp_path, self.config_path)
            try:
                with open(self.config_path, "rb") as src:
                    payload = src.read()
                with open(self.last_good_path, "wb") as dst:
                    dst.write(payload)
                try:
                    os.chmod(self.last_good_path, 0o600)
                except OSError:
                    pass
            except OSError:
                pass
            if self.want_singbox:
                self._restart_singbox()
            return True

    def refresh_once(self, fetcher=None, probe_pool: int = 0) -> bool:
        try:
            fetch = fetcher or self.fetcher
            csv_text = self._fetch_with_retry(fetch)
            nodes = snapshot_to_nodes(csv_text, limit=self.limit,
                                      probe_pool=probe_pool,
                                       probe_fn=lambda h, p: probe_tcp_latency(h, p, 5),
                                       real_topk=self.real_topk, dial_fn=self.dial_fn,
                                       singbox_bin=self.singbox_bin)
            if not nodes:
                return self._refresh_failed("no reachable nodes, kept previous")
        except Exception as exc:
            return self._refresh_failed(f"{type(exc).__name__}: {exc}")
        with self._lock:
            old_seen = dict(self._first_seen)
            now = _now_iso()
            current_keys = set()
            for node in nodes:
                key = f"{node['server']}:{node['server_port']}"
                current_keys.add(key)
                self._first_seen.setdefault(key, old_seen.get(key, now))
            for key in [k for k in self._first_seen if k not in current_keys]:
                del self._first_seen[key]
            self._nodes = nodes
            endpoints = nodes_to_endpoints(nodes)
            if self.preferred_tag not in {ep["tag"] for ep in endpoints}:
                if self.preferred_tag is not None:
                    self._record_history("preferred-gone",
                                         f"{self.preferred_tag} vanished, back to auto")
                self.preferred_tag = None
            final = self.preferred_tag or "auto"
        if not self._apply_config(final=final):
            return self._refresh_failed("config check failed, kept previous")
        with self._lock:
            self.status["endpoints"] = [
                {"tag": ep["tag"], "server": primary_server(ep)[0],
                 "server_port": primary_server(ep)[1],
                 "country": n.get("country", ""), "country_short": n.get("country_short", ""),
                 "latency_ms": n.get("latency_ms"), "real_latency_ms": n.get("real_latency_ms"),
                 "speed": n.get("speed", 0)}
                for ep, n in zip(endpoints, nodes)]
            self.status["countries"] = self._countries()
            self.status["preferred_tag"] = self.preferred_tag
            self.status["last_refresh"] = _now_iso()
            self.status["last_error"] = None
            self.status["refresh_ok"] += 1
            self._fail_streak = 0
            self._crash_streak = 0
        self._persist_nodes()
        self._persist_state()
        self._record_history("refresh-ok", f"{len(endpoints)} endpoints, final={final}")
        print(f"refreshed {len(endpoints)} endpoints, final={final}", flush=True)
        return True

    def _refresh_failed(self, reason: str) -> bool:
        with self._lock:
            self.status["last_error"] = reason
            self.status["refresh_fail"] += 1
            self._fail_streak += 1
        self._record_history("refresh-fail", reason)
        print(f"refresh failed: {reason}", flush=True)
        return False

    def _start_full_probe(self) -> None:
        with self._lock:
            self.status["full_probe"] = {"state": "running", "done": 0,
                                         "total": len(self._nodes)}
        thread = threading.Thread(target=self._run_full_probe, daemon=True)
        self._full_probe_thread = thread
        thread.start()

    def _run_full_probe(self) -> None:
        # Startup gate so /api/status readers can observe the "running"
        # state even when dial_fn returns instantly (e.g. in tests).
        time.sleep(0.2)
        nodes = list(self._nodes)
        with self._lock:
            self.status["full_probe"]["total"] = len(nodes)
        for i, node in enumerate(nodes):
            try:
                ms = self.dial_fn(node) if self.dial_fn else None
            except Exception:
                ms = None
            with self._lock:
                node["real_latency_ms"] = ms
                self.status["full_probe"]["done"] = i + 1
        with self._lock:
            self._sync_probe_results(nodes)
            self.status["full_probe"]["state"] = "done"
        self._record_history("full-probe-done",
                             f"{len(nodes)} nodes dialed")

    def _sync_probe_results(self, nodes: list[dict]) -> None:
        by_key = {(ep.get("server"), ep.get("server_port")): ep
                  for ep in self.status["endpoints"]}
        for i, node in enumerate(nodes):
            key = (node.get("server"), node.get("server_port"))
            if key in by_key:
                by_key[key]["real_latency_ms"] = node.get("real_latency_ms")
            else:
                entry = {"tag": f"vpngate-{i}", "server": node.get("server"),
                         "server_port": node.get("server_port"),
                         "country": node.get("country", ""),
                         "country_short": node.get("country_short", ""),
                         "latency_ms": node.get("latency_ms"),
                         "real_latency_ms": node.get("real_latency_ms"),
                         "speed": node.get("speed", 0)}
                self.status["endpoints"].append(entry)
                by_key[key] = entry

    def _fetch_with_retry(self, fetch) -> str:
        last_exc: Exception | None = None
        delays = [0] + list(self.retry_delays)
        for wait in delays:
            if wait:
                time.sleep(wait)
            try:
                return fetch(self.snapshot_url, 20)
            except Exception as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc

    def _check_config(self, path: str) -> bool:
        try:
            result = subprocess.run([self.singbox_bin, "check", "-c", path],
                                    capture_output=True, timeout=30)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _restart_singbox(self) -> None:
        with self._lock:
            self._terminate_singbox_locked()
            stderr_path = f"{self.config_path}.stderr.log"
            try:
                if (os.path.exists(stderr_path)
                        and os.path.getsize(stderr_path) > 200 * 1024):
                    os.unlink(stderr_path)
            except OSError:
                pass
            try:
                self._stderr_handle = open(stderr_path, "ab")
            except OSError:
                self._stderr_handle = None
            self._singbox_proc = subprocess.Popen(
                [self.singbox_bin, "run", "-c", self.config_path],
                stdout=subprocess.DEVNULL,
                stderr=self._stderr_handle or subprocess.DEVNULL,
            )

    def _terminate_singbox(self) -> None:
        with self._lock:
            self._terminate_singbox_locked()

    def _terminate_singbox_locked(self) -> None:
        proc, self._singbox_proc = self._singbox_proc, None
        handle, self._stderr_handle = self._stderr_handle, None
        if proc is None:
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass

    # -- cloudflare tunnel (soft-optional) -------------------------------
    def _start_cloudflared(self) -> bool:
        """Launch cloudflared for the VLESS+WS inbounds.

        Soft-skips (returns False, never raises/exits) when TUNNEL_TOKEN is
        empty or the binary is missing, so the proxy keeps working without a
        tunnel. Ingress rules (hostnames -> 8080/8082) live in the Cloudflare
        dashboard tunnel config, not here.
        """
        with self._lock:
            if not self.tunnel_token:
                self.status["tunnel"] = {"state": "no-token"}
                print("cloudflared skipped: TUNNEL_TOKEN not set", flush=True)
                return False
            binary = shutil.which(self.cloudflared_bin)
            if binary is None:
                self.status["tunnel"] = {"state": "no-binary",
                                         "binary": self.cloudflared_bin}
                print(f"cloudflared skipped: binary {self.cloudflared_bin!r} not found",
                      flush=True)
                return False
            try:
                self._cloudflared_proc = subprocess.Popen(
                    [binary, "tunnel", "--protocol", "quic", "--no-autoupdate",
                     "run", "--token", self.tunnel_token],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except OSError as exc:
                self.status["tunnel"] = {"state": "dead", "error": str(exc)}
                return False
            self.status["tunnel"] = {"state": "running", "since": _now_iso()}
            print("cloudflared tunnel started", flush=True)
            return True

    def _terminate_cloudflared(self) -> None:
        with self._lock:
            proc, self._cloudflared_proc = self._cloudflared_proc, None
            if proc is None:
                return
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
            self.status["tunnel"] = {"state": "off"}

    def tail_singbox_stderr(self, max_lines: int = 20) -> str:
        try:
            with open(f"{self.config_path}.stderr.log", "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - 16384))
                lines = handle.read().decode("utf-8", errors="replace").splitlines()
            return "\n".join(lines[-max_lines:])
        except OSError:
            return ""


def main() -> int:
    try:
        cfg = build_config_from_env(dict(os.environ))
    except SystemExit as exc:
        return int(exc.code or 1)
    if cfg["admin_token_generated"]:
        print(f"generated ADMIN_TOKEN={cfg['admin_token']} (save it to use /ui and /api)",
              flush=True)
    data_dir = cfg["data_dir"]
    os.makedirs(data_dir, exist_ok=True)
    manager = RailwayManager(
        port=cfg["port"],
        mixed_port=cfg["mixed_port"],
        username=cfg["username"],
        password=cfg["password"],
        admin_token=cfg["admin_token"],
        snapshot_url=cfg["snapshot_url"],
        refresh_seconds=cfg["refresh_seconds"],
        limit=cfg["limit"],
        real_topk=cfg["real_topk"],
        vless_uuid=cfg["vless_uuid"],
        vless_direct_port=cfg["vless_direct_port"],
        vless_chain_port=cfg["vless_chain_port"],
        tunnel_token=cfg["tunnel_token"],
        cloudflared_bin=cfg["cloudflared_bin"],
        config_path=os.path.join(data_dir, "singbox-railway.json"),
        nodes_path=os.path.join(data_dir, "nodes.json"),
        state_path=os.path.join(data_dir, "state.json"),
    )
    stop_event = threading.Event()

    def _on_signal(signum, frame) -> None:  # noqa: ARG001
        stop_event.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    manager.start()
    stop_event.wait()
    manager.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
