"""Railway entrypoint: single-$PORT multiplexer + sing-box supervisor (stdlib only).

Railway exposes exactly one ingress port ($PORT, HTTP) plus an optional raw
TCP Proxy. This process owns $PORT and dispatches by first bytes:

  0x05...          -> SOCKS5 handshake, piped to sing-box mixed inbound
  CONNECT ...      -> HTTP proxy request, piped to sing-box mixed inbound
  GET/POST/...     -> plain HTTP: /healthz (Railway healthcheck), /ui, /api/status
  anything else    -> closed

Outbound traffic leaves through sing-box openvpn-client endpoints
(system:false, internal stack, no TUN / no NET_ADMIN needed).
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import threading
import urllib.request
from datetime import datetime, timezone

from vpngate_to_singbox import build_singbox_config, snapshot_to_endpoints

DEFAULT_SNAPSHOT_URL = "https://www.vpngate.net/api/iphone/"
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                b"OPTIONS ", b"PATCH ")

UI_HTML = """\
<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vpngate-to-singbox</title></head>
<body style="font-family:sans-serif;max-width:720px;margin:2em auto">
<h1>vpngate-to-singbox</h1>
<p>SOCKS5/HTTP proxy (same port) -&gt; VPNGate over sing-box, no TUN.</p>
<table border="1" cellpadding="6" id="nodes">
<tr><th>endpoint</th><th>server</th><th>port</th></tr>
</table>
<p id="meta"></p>
<script>
async function refresh() {
  try {
    const r = await fetch("/api/status");
    const s = await r.json();
    document.getElementById("nodes").innerHTML =
      "<tr><th>endpoint</th><th>server</th><th>port</th></tr>" +
      s.endpoints.map(e => `<tr><td>${e.tag}</td><td>${e.server}</td><td>${e.server_port}</td></tr>`).join("");
    document.getElementById("meta").textContent =
      `last refresh: ${s.last_refresh} | error: ${s.last_error} | started: ${s.started_at}`;
  } catch (e) {
    document.getElementById("meta").textContent = "status fetch failed: " + e;
  }
}
refresh();
setInterval(refresh, 5000);
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


def default_fetch(url: str, timeout: int = 90) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _http_response(status: str, content_type: str, body: bytes) -> bytes:
    header = (f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n"
              f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return header.encode() + body


def _forward(source: socket.socket, dest: socket.socket) -> None:
    try:
        while True:
            chunk = source.recv(65536)
            if not chunk:
                break
            dest.sendall(chunk)
    except OSError:
        pass


class RailwayManager:
    def __init__(
        self,
        port: int = 8080,
        mixed_port: int = 40000,
        username: str = "u",
        password: str = "p",
        snapshot_url: str = DEFAULT_SNAPSHOT_URL,
        refresh_seconds: int = 1200,
        limit: int = 8,
        config_path: str = "singbox-railway.json",
        singbox_bin: str = "sing-box",
        start_singbox: bool = True,
        auto_refresh: bool = True,
        fetch_on_start: bool = True,
    ) -> None:
        self.port = port
        self.mixed_port = mixed_port
        self.username = username
        self.password = password
        self.snapshot_url = snapshot_url
        self.refresh_seconds = refresh_seconds
        self.limit = limit
        self.config_path = config_path
        self.singbox_bin = singbox_bin
        self.want_singbox = start_singbox
        self.auto_refresh = auto_refresh
        self.fetch_on_start = fetch_on_start
        self.status: dict = {
            "endpoints": [],
            "last_refresh": None,
            "last_error": None,
            "started_at": None,
            "proxy": f"127.0.0.1:{mixed_port}",
        }
        self._stop_event = threading.Event()
        self._listener: socket.socket | None = None
        self._singbox_proc: subprocess.Popen | None = None
        self.bound_port = port

    # -- lifecycle ------------------------------------------------------
    def start(self) -> int:
        if self.fetch_on_start:
            self.refresh_once()
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
        print(f"listening on 0.0.0.0:{self.bound_port}, backend 127.0.0.1:{self.mixed_port}",
              flush=True)
        return self.bound_port

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
        try:
            request_line = data.split(b"\r\n", 1)[0].decode("latin-1")
            _, path, _ = request_line.split(" ", 2)
        except ValueError:
            return
        path = path.split("?", 1)[0]
        if path == "/healthz":
            client.sendall(_http_response("200 OK", "text/plain", b"ok"))
        elif path == "/api/status":
            body = json.dumps(self.status).encode()
            client.sendall(_http_response("200 OK", "application/json", body))
        elif path in ("/", "/ui"):
            client.sendall(_http_response("200 OK", "text/html; charset=utf-8",
                                          UI_HTML.encode()))
        else:
            client.sendall(_http_response("404 Not Found", "text/plain", b"not found"))

    def _pipe_to_backend(self, client: socket.socket, peek: bytes) -> None:
        try:
            backend = socket.create_connection(("127.0.0.1", self.mixed_port), timeout=10)
        except OSError:
            return
        try:
            backend.sendall(peek)
            first = threading.Thread(target=_forward, args=(client, backend,), daemon=True)
            second = threading.Thread(target=_forward, args=(backend, client,), daemon=True)
            first.start()
            second.start()
            first.join()
            second.join()
        except OSError:
            pass
        finally:
            try:
                backend.close()
            except OSError:
                pass

    # -- snapshot refresh / sing-box supervision -------------------------
    def _refresh_loop(self) -> None:
        while not self._stop_event.wait(self.refresh_seconds):
            self.refresh_once()
            self._watchdog()

    def _watchdog(self) -> None:
        proc = self._singbox_proc
        if self.want_singbox and proc is not None and proc.poll() is not None:
            self.status["last_error"] = f"sing-box exited (code {proc.poll()})"

    def refresh_once(self, fetcher=None) -> bool:
        try:
            fetch = fetcher or default_fetch
            csv_text = fetch(self.snapshot_url, 90)
            endpoints = snapshot_to_endpoints(csv_text, limit=self.limit)
            config = build_singbox_config(
                endpoints, "127.0.0.1", self.mixed_port,
                mixed_users=[(self.username, self.password)],
            )
            with open(self.config_path, "w", encoding="utf-8") as handle:
                json.dump(config, handle, indent=2)
                handle.write("\n")
            if self.want_singbox:
                self._restart_singbox()
            self.status["endpoints"] = [
                {"tag": ep["tag"], "server": ep["server"], "server_port": ep["server_port"]}
                for ep in endpoints
            ]
            self.status["last_refresh"] = _now_iso()
            self.status["last_error"] = None
            print(f"refreshed {len(endpoints)} endpoints", flush=True)
            return True
        except Exception as exc:  # keep serving old config on failure
            self.status["last_error"] = f"{type(exc).__name__}: {exc}"
            print(f"refresh failed: {self.status['last_error']}", flush=True)
            return False

    def _restart_singbox(self) -> None:
        self._terminate_singbox()
        self._singbox_proc = subprocess.Popen(
            [self.singbox_bin, "run", "-c", self.config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _terminate_singbox(self) -> None:
        proc, self._singbox_proc = self._singbox_proc, None
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


def main() -> int:
    port = int(os.environ.get("PORT", "8080"))
    password = os.environ.get("PROXY_PASS", "p")
    if password == "p":
        print("WARNING: using default PROXY_PASS, set PROXY_PASS env for real deploys",
              flush=True)
    manager = RailwayManager(
        port=port,
        mixed_port=int(os.environ.get("MIXED_PORT", "40000")),
        username=os.environ.get("PROXY_USER", "u"),
        password=password,
        snapshot_url=os.environ.get("SNAPSHOT_URL", DEFAULT_SNAPSHOT_URL),
        refresh_seconds=int(os.environ.get("REFRESH_SECONDS", "1200")),
        limit=int(os.environ.get("LIMIT", "8")),
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
