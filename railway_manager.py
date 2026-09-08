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
CRASH_BACKOFFS = (5, 10, 20, 40, 300)
MAX_CRASH_STREAK = 5

UI_HTML = """\
<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vpngate-to-singbox</title></head>
<body style="font-family:sans-serif;max-width:720px;margin:2em auto">
<h1>vpngate-to-singbox</h1>
<p>SOCKS5/HTTP proxy (same port) -&gt; VPNGate over sing-box, no TUN.</p>
<div>
<label>Token: <input id="token" type="password" size="24"></label>
<button onclick="saveToken()">Save</button>
<label>Country: <select id="country"><option value="">auto</option></select></label>
<button onclick="switchCountry()">Switch</button>
<button onclick="refreshNow()">Refresh nodes</button>
</div>
<table border="1" cellpadding="6" id="nodes">
<tr><th>endpoint</th><th>country</th><th>server</th><th>port</th><th>latency</th><th>real</th></tr>
</table>
<p id="meta"></p>
<script>
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
async function refresh() {
  try {
    const s = await api("/api/status");
    const sel = document.getElementById("country");
    const cur = sel.value;
    sel.innerHTML = '<option value="">auto</option>' +
      s.countries.map(c => `<option value="${c.code}">${c.name} (${c.code})</option>`).join("");
    sel.value = cur;
    document.getElementById("nodes").innerHTML =
      "<tr><th>endpoint</th><th>country</th><th>server</th><th>port</th><th>latency</th><th>real</th></tr>" +
      s.endpoints.map(e => `<tr><td>${e.tag}${e.tag === s.preferred_tag ? " *pinned" : ""}</td><td>${e.country_short}</td><td>${e.server}</td><td>${e.server_port}</td><td>${e.latency_ms}ms</td><td>${e.real_latency_ms == null ? "-" : e.real_latency_ms + "ms"}</td></tr>`).join("");
    document.getElementById("meta").textContent =
      `pinned: ${s.preferred_tag} | refresh ok/fail: ${s.refresh_ok}/${s.refresh_fail} | uptime: ${s.uptime_seconds}s | error: ${s.last_error}`;
  } catch (e) {
    document.getElementById("meta").textContent = "status fetch failed: " + e;
  }
}
async function switchCountry() {
  const country = document.getElementById("country").value;
  await api("/api/switch", "POST", country ? {"country": country} : {"tag": "auto"});
  refresh();
}
async function refreshNow() {
  await api("/api/refresh", "POST", {});
  refresh();
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
        "real_topk": int(env.get("REAL_TOPK", "5")),
        "data_dir": env.get("DATA_DIR", "."),
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
        self.dial_fn = dial_fn
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
        }
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
        print(f"listening on 0.0.0.0:{self.bound_port}, backend 127.0.0.1:{self.mixed_port}",
              flush=True)
        return self.bound_port

    def _initial_refresh(self) -> None:
        if not self.refresh_once():
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
                mixed_users=[(self.username, self.password)], final=final)
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

    def refresh_once(self, fetcher=None) -> bool:
        try:
            fetch = fetcher or self.fetcher
            csv_text = self._fetch_with_retry(fetch)
            nodes = snapshot_to_nodes(csv_text, limit=self.limit,
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
