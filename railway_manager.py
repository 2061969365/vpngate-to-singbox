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
    measure_exit_ip,
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
PIPE_IDLE_TIMEOUT = 300
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
body{background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(ellipse 55% 40% at 75% 8%,rgba(99,102,241,.28),transparent 70%),radial-gradient(ellipse 45% 35% at 12% 25%,rgba(34,211,238,.16),transparent 70%),radial-gradient(ellipse 50% 45% at 50% 100%,rgba(16,185,129,.14),transparent 70%),#000}
#topnav{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:26px;padding:14px 32px;font-size:14px;background:rgba(10,12,24,.72);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-bottom:1px solid rgba(255,255,255,.09)}
#topnav .logo{font-weight:800;font-size:16px;background:linear-gradient(90deg,#a5b4fc,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
#topnav .live{font-size:11px;color:#6ee7b7;border:1px solid rgba(110,231,183,.4);border-radius:999px;padding:2px 10px}
#topnav .links{display:flex;gap:22px;color:#ccc}
#topnav .right{margin-left:auto;display:flex;gap:14px;align-items:center}
#topnav input{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);color:#fff;border-radius:10px;padding:7px 12px;font-size:13px}
#topnav .cta{border:1px solid rgba(255,255,255,.2);border-radius:999px;padding:7px 18px;cursor:pointer;background:rgba(255,255,255,.06)}
#topnav .cta:hover{background:rgba(255,255,255,.14)}
.wrap{max-width:1180px;margin:0 auto;padding:34px 28px 60px}
.glass-card{background:rgba(255,255,255,.055);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.11);border-radius:22px;padding:28px 30px;margin-bottom:22px;box-shadow:0 18px 50px rgba(0,0,0,.45)}
.glass-card h2{font-size:19px;font-weight:700;margin-bottom:6px}
.glass-card .desc{color:#a8adbd;font-size:13px;line-height:1.7;margin-bottom:16px}
#exit-card{background:linear-gradient(135deg,rgba(99,102,241,.2),rgba(34,211,238,.1)),rgba(255,255,255,.055)}
#hero-kicker{font-size:52px;font-weight:800;letter-spacing:-.03em;line-height:1.08;background:linear-gradient(92deg,#fff,#a5b4fc 60%,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
#hero-sub{color:#c2c7d6;font-size:14px;margin-top:10px}
#verify-result{margin-top:12px;font-size:14px;color:#6ee7b7;min-height:22px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
.stat{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:16px 18px;backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}
.stat .k{font-size:12px;color:#8b91a5}
.stat .v{font-size:24px;font-weight:700;margin-top:4px}
.btn{border-radius:999px;padding:10px 24px;font-size:14px;cursor:pointer;border:1px solid rgba(255,255,255,.2);color:#fff;background:rgba(255,255,255,.07);transition:transform .12s ease,background .15s ease}
.btn:hover{background:rgba(255,255,255,.15)}
.btn:active{transform:scale(.97)}
.btn:disabled{opacity:.55;cursor:wait;transform:none}
.btn.primary{background:linear-gradient(92deg,#6366f1,#0ea5e9);border:none;font-weight:600;box-shadow:0 6px 24px rgba(99,102,241,.45)}
.btn.busy{animation:pulse 1.1s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
#pills{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}
#pills span{border:1px solid rgba(255,255,255,.16);border-radius:999px;padding:7px 18px;font-size:13px;color:#ddd;cursor:pointer;background:rgba(255,255,255,.04)}
#pills span.on{background:linear-gradient(92deg,#6366f1,#0ea5e9);color:#fff;border-color:transparent}
.actions{display:flex;gap:12px;margin-top:16px;flex-wrap:wrap}
#btn-verify{background:linear-gradient(92deg,#6366f1,#0ea5e9);color:#fff;border-radius:999px;padding:10px 26px;font-size:14px;font-weight:600;cursor:pointer;border:none;box-shadow:0 6px 24px rgba(99,102,241,.45)}
#btn-refresh{border:1px solid rgba(255,255,255,.2);border-radius:999px;padding:10px 26px;font-size:14px;color:#fff;background:rgba(255,255,255,.07);cursor:pointer}
#btn-fullprobe{border:1px solid rgba(138,180,255,.55);border-radius:999px;padding:10px 26px;font-size:14px;color:#8ab4ff;background:rgba(138,180,255,.08);cursor:pointer}
#btn-verify:disabled,#btn-refresh:disabled,#btn-fullprobe:disabled{opacity:.55;cursor:wait}
#node-search{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);color:#fff;border-radius:10px;padding:8px 14px;font-size:13px;width:230px}
table.bench{width:100%;border-collapse:collapse;font-size:14px}
table.bench th,table.bench td{text-align:left;padding:11px 14px;border-bottom:1px solid rgba(255,255,255,.08)}
table.bench th{color:#8b91a5;font-weight:500;font-size:12px}
table.bench tr:hover td{background:rgba(255,255,255,.035)}
table.bench td.hl{color:#fff;font-weight:600}
table.bench td.op a{color:#8ab4ff;cursor:pointer;text-decoration:none;margin-right:12px}
table.bench td.op a:hover{text-decoration:underline}
.badge{display:inline-block;font-size:11px;border-radius:999px;padding:2px 10px;margin-left:8px;background:linear-gradient(92deg,#6366f1,#0ea5e9);color:#fff}
.badge.probing{background:rgba(251,191,36,.18);color:#fbbf24;border:1px solid rgba(251,191,36,.4)}
#probe-progress{display:none;margin:14px 0 4px}
#probe-progress.show{display:block}
#probe-progress .bar{height:8px;border-radius:999px;background:rgba(255,255,255,.1);overflow:hidden}
#probe-progress .fill{height:100%;width:0;border-radius:999px;background:linear-gradient(90deg,#6366f1,#22d3ee);transition:width .4s ease}
#probe-progress .txt{font-size:12px;color:#8b91a5;margin-top:6px}
#history-line{color:#8b91a5;font-size:13px;margin-top:14px}
#history-list{list-style:none;margin-top:10px;max-height:220px;overflow:auto}
#history-list li{font-size:12.5px;color:#a8adbd;padding:7px 4px;border-bottom:1px dashed rgba(255,255,255,.08)}
#history-list li b{color:#e5e7eb;font-weight:600}
#toast{position:fixed;right:22px;bottom:22px;z-index:100;display:flex;flex-direction:column;gap:10px}
.toast-msg{background:rgba(16,20,36,.92);border:1px solid rgba(110,231,183,.45);color:#d1fae5;border-radius:14px;padding:12px 18px;font-size:13px;max-width:360px;box-shadow:0 10px 30px rgba(0,0,0,.5);animation:slidein .25s ease}
.toast-msg.err{border-color:rgba(248,113,113,.55);color:#fecaca}
@keyframes slidein{from{transform:translateY(12px);opacity:0}to{transform:none;opacity:1}}
.footer{color:#69707f;font-size:12.5px;text-align:center;padding:10px 0 30px}
#login-gate{position:fixed;inset:0;z-index:200;display:flex;align-items:center;justify-content:center;padding:20px;background:radial-gradient(ellipse 55% 40% at 75% 8%,rgba(99,102,241,.28),transparent 70%),radial-gradient(ellipse 45% 35% at 12% 25%,rgba(34,211,238,.16),transparent 70%),rgba(0,0,0,.72);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
#login-gate.hidden{display:none}
.login-card{width:380px;max-width:92vw;text-align:center;padding:40px 36px}
.login-card .logo{font-weight:800;font-size:22px;background:linear-gradient(90deg,#a5b4fc,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
.login-card .sub{color:#8b91a5;font-size:13px;margin:10px 0 22px}
#login-token{width:100%;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.16);color:#fff;border-radius:12px;padding:12px 16px;font-size:14px;margin-bottom:14px;text-align:center}
#btn-login{width:100%;background:linear-gradient(92deg,#6366f1,#0ea5e9);color:#fff;border-radius:12px;padding:12px;font-size:15px;font-weight:600;cursor:pointer;border:none;box-shadow:0 6px 24px rgba(99,102,241,.45)}
#btn-login:disabled{opacity:.55;cursor:wait}
#login-err{color:#fca5a5;font-size:13px;min-height:20px;margin-top:12px}
.shake{animation:shake .4s ease}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-8px)}75%{transform:translateX(8px)}}
#console.hidden{display:none}
#btn-lock{border:1px solid rgba(255,255,255,.2);border-radius:999px;padding:7px 18px;cursor:pointer;background:rgba(255,255,255,.06);font-size:13px;color:#ddd}
#btn-lock:hover{background:rgba(255,255,255,.14)}
@media(max-width:768px){#hero-kicker{font-size:34px}.wrap{padding:20px 14px 44px}.stats{grid-template-columns:repeat(2,1fr)}#topnav .links{display:none}}
</style></head>
<body>
<div id="topnav"><span class="logo">vpngate</span><span class="live">● LIVE</span><span class="links"><span>总览</span><span>节点</span><span>历史</span></span><span class="right"><button id="btn-lock" onclick="lockConsole()">锁定</button></span></div>
<div id="login-gate"><div class="login-card glass-card"><div class="logo">vpngate</div><div class="sub">输入 ADMIN_TOKEN 进入控制台</div><input id="login-token" type="password" placeholder="ADMIN_TOKEN" onkeydown="if(event.key==='Enter')loginEnter()"><button id="btn-login" onclick="loginEnter()">进入控制台</button><p id="login-err"></p></div></div>
<div class="wrap" id="console" style="display:none">
<div id="exit-card" class="glass-card">
<div id="hero-kicker">—<br>—</div>
<p id="hero-sub">loading…</p>
<p id="verify-result"></p>
<div class="actions"><button id="btn-verify" onclick="verifyExit()">验证出口 IP</button></div>
</div>
<div class="stats">
<div class="stat"><div class="k">可用节点</div><div class="v" id="stat-nodes">—</div></div>
<div class="stat"><div class="k">最优实测</div><div class="v" id="stat-best">—</div></div>
<div class="stat"><div class="k">运行时间</div><div class="v" id="stat-uptime">—</div></div>
<div class="stat"><div class="k">刷新成功/失败</div><div class="v" id="stat-refresh">—</div></div>
</div>
<div class="glass-card">
<h2>可用节点</h2>
<p class="desc">默认显示 Top30 实测节点（自动刷新只测前 30）。Speed 排名不等于可拨通，首选由 urltest 实测决定，多 endpoint 兜底；要测全部点「全量真测」。</p>
<div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap"><input id="node-search" placeholder="搜索 tag / 国家…" oninput="refresh()"><button id="btn-refresh" class="btn" onclick="refreshNow()">刷新节点</button><button id="btn-fullprobe" class="btn" onclick="fullProbeNow()">全量真测</button></div>
<div id="pills"></div>
<div id="probe-progress"><div class="bar"><div class="fill" id="probe-fill"></div></div><div class="txt" id="probe-txt"></div></div>
<table class="bench"><thead><tr><th>Endpoint</th><th>国家</th><th>握手</th><th>实测</th><th>存活</th><th>操作</th></tr></thead><tbody id="bench-body"></tbody></table>
</div>
<div class="glass-card">
<h2>事件</h2>
<p class="desc">刷新 / 切换 / 测速 / 验证记录，最近 20 条。</p>
<p id="history-line"></p>
<ul id="history-list"></ul>
</div>
<div class="footer"><span id="foot-status">—</span><span> · 自用调试 · sing-box 内部协议栈 · 无 TUN</span></div>
</div>
<div id="toast"></div>
<script>
var activeCountry = "";
var lastStatus = null;
function authHeaders() {
  return {"Authorization": "Bearer " + (localStorage.getItem("admin_token") || "")};
}
function showConsole() {
  document.getElementById("login-gate").classList.add("hidden");
  document.getElementById("console").style.display = "";
  refresh();
}
function lockConsole() {
  localStorage.removeItem("admin_token");
  document.getElementById("console").style.display = "none";
  const gate = document.getElementById("login-gate");
  gate.classList.remove("hidden");
  document.getElementById("login-token").value = "";
  document.getElementById("login-err").textContent = "";
}
async function loginEnter() {
  const input = document.getElementById("login-token");
  const btn = document.getElementById("btn-login");
  const err = document.getElementById("login-err");
  const trial = input.value.trim();
  if (!trial) { err.textContent = "请先填写 token"; return; }
  btn.disabled = true;
  btn.textContent = "验证中…";
  err.textContent = "";
  localStorage.setItem("admin_token", trial);
  try {
    await api("/api/status");
    showConsole();
  } catch (e) {
    localStorage.removeItem("admin_token");
    err.textContent = "token 不对，请重试";
    const card = document.querySelector(".login-card");
    card.classList.remove("shake");
    void card.offsetWidth;
    card.classList.add("shake");
  }
  btn.disabled = false;
  btn.textContent = "进入控制台";
}
async function silentLogin() {
  if (!localStorage.getItem("admin_token")) return;
  try {
    await api("/api/status");
    showConsole();
  } catch (e) {
    localStorage.removeItem("admin_token");
  }
}
function toast(msg, isErr) {
  const box = document.getElementById("toast");
  const el = document.createElement("div");
  el.className = "toast-msg" + (isErr ? " err" : "");
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}
function setBusy(id, busy, busyText) {
  const el = document.getElementById(id);
  if (!el) return;
  if (busy) {
    if (el.dataset.orig === undefined) el.dataset.orig = el.textContent;
    el.disabled = true;
    el.classList.add("busy");
    el.textContent = busyText || "进行中…";
  } else {
    el.disabled = false;
    el.classList.remove("busy");
    if (el.dataset.orig !== undefined) el.textContent = el.dataset.orig;
  }
}
async function api(path, method, body) {
  const r = await fetch(path, {method: method || "GET", headers: authHeaders(),
    body: body ? JSON.stringify(body) : undefined});
  if (r.status === 401) throw new Error("unauthorized: save ADMIN_TOKEN first");
  if (!r.ok) throw new Error("HTTP " + r.status + ": " + (await r.text()).slice(0, 160));
  return r.json();
}
function fmtMs(v) { return v == null ? "—" : v + "ms"; }
function safeTag(t) { return String(t || "").replace(/[^a-zA-Z0-9-_]/g, ""); }
function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
function nodeQuery() { const el = document.getElementById("node-search"); return el ? el.value.trim().toLowerCase() : ""; }
async function refresh() {
  try {
    const s = await api("/api/status");
    lastStatus = s;
    const q = nodeQuery();
    const eps = s.endpoints.filter(e => (!activeCountry || e.country_short === activeCountry) &&
      (!q || (e.tag || "").toLowerCase().includes(q) || (e.country_short || "").toLowerCase().includes(q)));
    const pref = s.endpoints.find(e => e.tag === s.preferred_tag) || eps[0];
    document.getElementById("hero-kicker").innerHTML =
      (pref ? esc(pref.country_short) + "<br>" + fmtMs(pref.real_latency_ms != null ? pref.real_latency_ms : pref.latency_ms) : "—<br>无节点");
    document.getElementById("hero-sub").textContent =
      pref ? ("经 " + pref.tag + " 出站 · " + pref.server + ":" + pref.server_port + " · 存活 " + (pref.alive_seconds || 0) + "s") : "暂无可用节点";
    renderVerify(s.verify, pref);
    document.getElementById("stat-nodes").textContent = s.endpoints.length;
    const measured = s.endpoints.filter(e => e.real_latency_ms != null).map(e => e.real_latency_ms);
    document.getElementById("stat-best").textContent = measured.length ? Math.min.apply(null, measured) + "ms" : "—";
    document.getElementById("stat-uptime").textContent = Math.floor((s.uptime_seconds || 0) / 60) + "m";
    document.getElementById("stat-refresh").textContent = s.refresh_ok + "/" + s.refresh_fail;
    document.getElementById("pills").innerHTML =
      '<span data-c="" class="' + (activeCountry === "" ? "on" : "") + '">全部 ' + s.endpoints.length + "</span>" +
      s.countries.map(c => '<span data-c="' + c.code + '" class="' + (activeCountry === c.code ? "on" : "") + '">' + esc(c.name) + "</span>").join("");
    document.querySelectorAll("#pills span").forEach(el => el.onclick = () => { activeCountry = el.getAttribute("data-c"); refresh(); });
    const probingTag = (s.probe && s.probe.state === "running") ? s.probe.tag : null;
    document.getElementById("bench-body").innerHTML = eps.map(e => {
      const t = safeTag(e.tag);
      const pinned = e.tag === s.preferred_tag ? '<span class="badge">pinned</span>' : "";
      const probing = e.tag === probingTag ? '<span class="badge probing">测速中</span>' : "";
      return "<tr><td class='hl'>" + esc(e.tag) + pinned + probing + "</td><td>" + esc(e.country_short) + "</td><td class='hl'>" + fmtMs(e.latency_ms) +
      "</td><td class='hl'>" + fmtMs(e.real_latency_ms) + "</td><td>" + (e.alive_seconds || 0) + "s</td>" +
      "<td class='op'><a data-probe='" + t + "'>测速</a><a data-switch='" + t + "'>切换</a></td></tr>";
    }).join("");
    renderProbeProgress(s.full_probe);
    document.getElementById("history-line").textContent =
      "refresh ok/fail: " + s.refresh_ok + "/" + s.refresh_fail + " · uptime: " + s.uptime_seconds + "s · error: " + s.last_error;
    document.getElementById("history-list").innerHTML =
      (s.refresh_history || []).slice().reverse().slice(0, 12).map(h => "<li><b>" + esc(h.event) + "</b> " + esc(h.detail || "") + " · " + esc(h.ts || "") + "</li>").join("");
    document.getElementById("foot-status").textContent = "uptime " + s.uptime_seconds + "s · refresh " + s.refresh_ok + "/" + s.refresh_fail;
  } catch (e) {
    document.getElementById("hero-sub").textContent = "status fetch failed: " + e;
    toast("状态拉取失败: " + e.message, true);
  }
}
function renderVerify(v, pref) {
  const el = document.getElementById("verify-result");
  if (!v || v.state === "idle") {
    el.textContent = pref ? "尚未验证当前出口，点击「验证出口 IP」真实走一次 VPN 链路。" : "";
    return;
  }
  if (v.state === "running") {
    el.textContent = "正在经 " + (v.via_tag || "…") + " 验证出口…";
    return;
  }
  el.textContent = v.exit_ip ? ("当前出口 IP：" + v.exit_ip + "（经 " + v.via_tag + "，" + v.ms + "ms）")
    : ("验证失败" + (v.error ? "：" + v.error : ""));
}
function renderProbeProgress(fp) {
  const box = document.getElementById("probe-progress");
  if (!fp || fp.state === "idle" || !fp.total) { box.classList.remove("show"); return; }
  box.classList.add("show");
  const pct = fp.total ? Math.round(fp.done / fp.total * 100) : 0;
  document.getElementById("probe-fill").style.width = pct + "%";
  document.getElementById("probe-txt").textContent = "全量真测 " + fp.state + " " + fp.done + "/" + fp.total + "（" + pct + "%）";
}
async function switchTag(tag) {
  try {
    const r = await api("/api/switch", "POST", {"tag": tag});
    toast("已切换到 " + (r.preferred_tag || tag));
  } catch (e) { toast("切换失败: " + e.message, true); }
  refresh();
}
async function probeOne(tag) {
  try {
    await api("/api/probe", "POST", {"tag": tag});
    toast("单测 " + tag + " 进行中…");
    for (let i = 0; i < 40; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const s = await api("/api/status");
      lastStatus = s;
      renderProbeProgress(s.full_probe);
      if (s.probe && s.probe.state === "done" && s.probe.tag === tag) {
        toast(s.probe.ms != null ? ("单测 " + tag + " 完成：" + s.probe.ms + "ms") : ("单测 " + tag + " 未打通"));
        break;
      }
    }
  } catch (e) { toast("单测失败: " + e.message, true); }
  refresh();
}
async function refreshNow() {
  setBusy("btn-refresh", true, "刷新中…");
  try {
    const r = await api("/api/refresh", "POST", {});
    toast(r.ok ? "节点已刷新" : "刷新完成但有失败");
  } catch (e) { toast("刷新失败: " + e.message, true); }
  setBusy("btn-refresh", false);
  refresh();
}
async function fullProbeNow() {
  setBusy("btn-fullprobe", true, "真测中…");
  try {
    await api("/api/full_probe", "POST", {});
    toast("全量真测已开始，后台逐个拨号…");
    for (let i = 0; i < 200; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const s = await api("/api/status");
      lastStatus = s;
      renderProbeProgress(s.full_probe);
      if (s.full_probe && s.full_probe.state === "done") {
        toast("全量真测完成：" + s.full_probe.done + "/" + s.full_probe.total);
        break;
      }
    }
  } catch (e) { toast("全量真测失败: " + e.message, true); }
  setBusy("btn-fullprobe", false);
  refresh();
}
async function verifyExit() {
  setBusy("btn-verify", true, "验证中…");
  document.getElementById("verify-result").textContent = "正在建立 VPN 链路并抓取出口 IP…";
  try {
    await api("/api/verify", "POST", {});
    for (let i = 0; i < 40; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const s = await api("/api/status");
      lastStatus = s;
      renderVerify(s.verify);
      if (s.verify && s.verify.state === "done") {
        toast(s.verify.exit_ip ? ("出口 IP：" + s.verify.exit_ip) : "验证未拿到出口 IP", !s.verify.exit_ip);
        break;
      }
    }
  } catch (e) {
    document.getElementById("verify-result").textContent = "";
    toast("验证失败: " + e.message, true);
  }
  setBusy("btn-verify", false);
  refresh();
}
silentLogin();
document.getElementById("bench-body").onclick = (ev) => {
  const link = ev.target && ev.target.closest ? ev.target.closest("a") : null;
  if (!link) return;
  const p = link.getAttribute("data-probe");
  const sw = link.getAttribute("data-switch");
  if (p) probeOne(p);
  else if (sw) switchTag(sw);
};
setInterval(() => { if (document.getElementById("console").style.display !== "none") refresh(); }, 15000);
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
    password = env.get("PROXY_PASS", "")
    if not password:
        password = secrets.token_urlsafe(24)
        print("PROXY_PASS not set, generated a random one", flush=True)
    elif len(password) < MIN_PROXY_PASS_LEN:
        print(f"refusing to start: PROXY_PASS must be at least {MIN_PROXY_PASS_LEN} chars",
              flush=True)
        raise SystemExit(2)
    snapshot_url = env.get("SNAPSHOT_URL", DEFAULT_SNAPSHOT_URL)
    if urllib.parse.urlsplit(snapshot_url).scheme != "https":
        print("refusing to start: SNAPSHOT_URL must be https", flush=True)
        raise SystemExit(2)
    if "ADMIN_TOKEN" not in env or not env["ADMIN_TOKEN"]:
        admin_token = "vpn"
        generated = False
        print("ADMIN_TOKEN not set, defaulting to 'vpn'", flush=True)
    else:
        admin_token = env["ADMIN_TOKEN"]
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
        "dial_workers": int(env.get("DIAL_WORKERS", "10")),
        "data_dir": env.get("DATA_DIR")
        or env.get("RAILWAY_VOLUME_MOUNT_PATH") or ".",
        "vless_uuid": env.get("VLESS_UUID", ""),
        "vless_direct_port": int(env.get("VLESS_DIRECT_PORT", "8080")),
        "vless_chain_port": int(env.get("VLESS_CHAIN_PORT", "8082")),
        "tunnel_token": env.get("TUNNEL_TOKEN", ""),
        "cloudflared_bin": env.get("CLOUDFLARED_BIN", "cloudflared"),
        "disguise_path": env.get("DISGUISE_PATH", ""),
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _http_response(status: str, content_type: str, body: bytes) -> bytes:
    header = (f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n"
              f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return header.encode() + body


def _forward(source: socket.socket, dest: socket.socket) -> int:
    """Forward until EOF/error/idle-timeout, returning bytes moved."""
    moved = 0
    try:
        while True:
            try:
                chunk = source.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            dest.sendall(chunk)
            moved += len(chunk)
    except OSError:
        pass
    return moved


def _reap_process(proc, handle=None) -> None:
    """Terminate and reap a child process. Must run WITHOUT holding locks:
    wait() can block for seconds and would stall health/API handlers."""
    if proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
    if handle is not None:
        try:
            handle.close()
        except OSError:
            pass


def _is_partial_token(data: bytes) -> bool:
    """True when data could still become a known first token (TCP split)."""
    if not data:
        return False
    for token in HTTP_METHODS + (b"CONNECT ",):
        if len(data) < len(token) and token.startswith(data):
            return True
    return False


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
        dial_workers: int = 10,
        verify_fn=None,
        vless_uuid: str = "",
        vless_direct_port: int = 8080,
        vless_chain_port: int = 8082,
        tunnel_token: str = "",
        cloudflared_bin: str = "cloudflared",
        disguise_path: str = "",
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
        self.dial_workers = dial_workers
        self.verify_fn = (verify_fn if verify_fn is not None else
                          (lambda endpoint: measure_exit_ip(
                              endpoint, self.singbox_bin)))
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
        self.disguise_path = disguise_path
        self._cloudflared_proc: subprocess.Popen | None = None
        self.preferred_tag: str | None = None
        self._nodes: list[dict] = []
        self._first_seen: dict[str, str] = {}
        self._fail_streak = 0
        self._pinned_fail_streak = 0
        self._crash_streak = 0
        self._retry_after = 0.0
        self._lock = threading.RLock()
        self._refresh_lock = threading.Lock()
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
            "probe": {"state": "idle", "tag": None, "ms": None, "error": None},
            "verify": {"state": "idle", "exit_ip": None, "ms": None,
                       "via_tag": None, "error": None},
            "tunnel": {"state": "off"},
        }
        self._full_probe_thread: threading.Thread | None = None
        self._single_probe_thread: threading.Thread | None = None
        self._verify_thread: threading.Thread | None = None
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
            if kind == "unknown" and _is_partial_token(peek):
                # TCP split the request head ("GE"+"T /..."): wait for
                # more bytes instead of dropping a valid connection.
                deadline = time.monotonic() + 5
                while (len(peek) < 4096
                       and time.monotonic() < deadline):
                    try:
                        chunk = client.recv(4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    peek += chunk
                    kind = classify_first_bytes(peek)
                    if kind != "unknown" or not _is_partial_token(peek):
                        break
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
        if path == "/" and method == "GET":
            body = self._disguise_body()
            if body is not None:
                client.sendall(_http_response("200 OK", "text/html; charset=utf-8",
                                              body))
            else:
                client.sendall(_http_response("200 OK", "text/html; charset=utf-8",
                                              UI_HTML.encode()))
            return
        if path == "/ui" and method == "GET":
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
        elif path == "/api/probe" and method == "POST":
            try:
                payload = json.loads((body or b"{}").decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                payload = None
            if not isinstance(payload, dict) or not payload.get("tag"):
                client.sendall(_http_response("400 Bad Request", "text/plain",
                                              b"missing tag"))
                return
            node = next((n for n in self._nodes
                         if n.get("endpoint", {}).get("tag") == payload["tag"]),
                        None)
            if node is None:
                client.sendall(_http_response(
                    "404 Not Found", "application/json",
                    json.dumps({"ok": False, "error": "unknown tag"}).encode()))
                return
            self._start_single_probe(node)
            client.sendall(_http_response(
                "202 Accepted", "application/json",
                json.dumps({"accepted": True,
                            "tag": node["endpoint"]["tag"]}).encode()))
        elif path == "/api/verify" and method == "POST":
            node = self._verify_target_node()
            if node is None:
                client.sendall(_http_response(
                    "503 Service Unavailable", "application/json",
                    json.dumps({"ok": False,
                                "error": "no nodes"}).encode()))
                return
            self._start_verify(node)
            client.sendall(_http_response(
                "202 Accepted", "application/json",
                json.dumps({"accepted": True,
                            "via_tag": node.get("endpoint", {}).get("tag")}).encode()))
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

    def _disguise_body(self) -> bytes | None:
        """Disguise page bytes for GET /, or None to fall back to the console."""
        if not self.disguise_path:
            return None
        try:
            with open(self.disguise_path, "rb") as handle:
                return handle.read()
        except OSError:
            return None

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
        client.settimeout(PIPE_IDLE_TIMEOUT)
        backend.settimeout(PIPE_IDLE_TIMEOUT)
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
            # One direction ended: unblock the other so join() below
            # always returns instead of parking threads forever.
            for sock in (client, backend):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            second.join(timeout=10)
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
            try:
                self.refresh_once()
            except Exception as exc:  # never kill the refresh thread
                print(f"refresh loop error: {type(exc).__name__}: {exc}", flush=True)
            next_run = (time.monotonic() + self._effective_interval()
                        + random.uniform(-30, 30))

    def _supervise_loop(self) -> None:
        while not self._stop_event.wait(SUPERVISE_INTERVAL):
            try:
                self._supervise_once()
            except Exception as exc:  # never kill the supervise thread
                print(f"supervise loop error: {type(exc).__name__}: {exc}", flush=True)

    def _supervise_once(self) -> None:
        with self._lock:
            if not self.want_singbox:
                return
            proc = self._singbox_proc
            if proc is not None and proc.poll() is None:
                self._crash_streak = 0
                return
            if proc is None and not os.path.exists(self.config_path):
                return
            now = time.monotonic()
            if self._crash_streak >= MAX_CRASH_STREAK:
                return  # wait for next successful refresh to reset
            if now < self._retry_after:
                return
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
            username, password = self.username, self.password
            mixed_port = self.mixed_port
            vless_uuid = self.vless_uuid or None
            direct_port = self.vless_direct_port
            chain_port = self.vless_chain_port
            config_path = self.config_path
            last_good_path = self.last_good_path
            want_singbox = self.want_singbox
        config = build_singbox_config(
            endpoints, "127.0.0.1", mixed_port,
            mixed_users=[(username, password)], final=final,
            vless_uuid=vless_uuid,
            vless_direct_port=direct_port,
            vless_chain_port=chain_port)
        # Everything below runs WITHOUT the lock: `sing-box check` may
        # block ~30s and restart waits on the old process; holding the
        # lock here would stall /healthz and every /api/* handler.
        tmp_path = f"{config_path}.tmp-{os.getpid()}"
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
        os.replace(tmp_path, config_path)
        try:
            with open(config_path, "rb") as src:
                payload = src.read()
            with open(last_good_path, "wb") as dst:
                dst.write(payload)
            try:
                os.chmod(last_good_path, 0o600)
            except OSError:
                pass
        except OSError:
            pass
        if want_singbox:
            self._restart_singbox()
        return True

    def refresh_once(self, fetcher=None, probe_pool: int = 0) -> bool:
        # Manual (/api/refresh), scheduled (_refresh_loop) and boot
        # (_initial_refresh) refreshes must never interleave: two of them
        # writing tmp-*/nodes/state at once corrupts the config.
        if not self._refresh_lock.acquire(blocking=False):
            self._record_history("refresh-busy",
                                 "skipped: another refresh in progress")
            return False
        try:
            return self._refresh_once_inner(fetcher, probe_pool)
        finally:
            self._refresh_lock.release()

    def _refresh_once_inner(self, fetcher=None, probe_pool: int = 0) -> bool:
        try:
            fetch = fetcher or self.fetcher
            csv_text = self._fetch_with_retry(fetch)
            nodes = snapshot_to_nodes(csv_text, limit=self.limit,
                                      probe_pool=probe_pool,
                                       probe_fn=lambda h, p: probe_tcp_latency(h, p, 5),
                                       real_topk=self.real_topk, dial_fn=self.dial_fn,
                                       dial_workers=self.dial_workers,
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

    def _start_single_probe(self, node: dict) -> None:
        with self._lock:
            tag = node.get("endpoint", {}).get("tag")
            self.status["probe"] = {"state": "running", "tag": tag,
                                    "ms": None, "error": None}
        thread = threading.Thread(target=self._run_single_probe, args=(node,),
                                  daemon=True)
        self._single_probe_thread = thread
        thread.start()

    def _run_single_probe(self, node: dict) -> None:
        # No startup gate here (unlike the full probe): the caller polls
        # /api/status for state==done, and an instant dial_fn in tests still
        # lands "done" only after the thread actually ran.
        tag = node.get("endpoint", {}).get("tag")
        try:
            ms = self.dial_fn(node)
            error = None
        except Exception as exc:
            ms = None
            error = f"{type(exc).__name__}: {exc}"
        with self._lock:
            node["real_latency_ms"] = ms
            key = (node.get("server"), node.get("server_port"))
            for ep in self.status["endpoints"]:
                if (ep.get("server"), ep.get("server_port")) == key:
                    ep["real_latency_ms"] = ms
                    break
            # The node was already in the sing-box config (every live node
            # gets an endpoint at refresh), so a measured node is immediately
            # switchable -- no config rebuild needed.
            self.status["probe"] = {"state": "done", "tag": tag,
                                    "ms": ms, "error": error}
        self._record_history("single-probe", f"{tag} ms={ms}")

    def _verify_target_node(self) -> dict | None:
        """Node backing the live chain: pinned preferred, else first node."""
        if self.preferred_tag:
            for node in self._nodes:
                if node.get("endpoint", {}).get("tag") == self.preferred_tag:
                    return node
        return self._nodes[0] if self._nodes else None

    def _start_verify(self, node: dict) -> None:
        with self._lock:
            tag = node.get("endpoint", {}).get("tag")
            self.status["verify"] = {"state": "running", "exit_ip": None,
                                     "ms": None, "via_tag": tag,
                                     "error": None}
        thread = threading.Thread(target=self._run_verify, args=(node,),
                                  daemon=True)
        self._verify_thread = thread
        thread.start()

    def _run_verify(self, node: dict) -> None:
        # Startup gate so /api/status readers can observe the "running"
        # state even when verify_fn returns instantly (e.g. in tests).
        time.sleep(0.2)
        tag = node.get("endpoint", {}).get("tag")
        endpoint = node.get("endpoint") or node
        try:
            result = self.verify_fn(endpoint)
            exit_ip, ms = result if result else (None, None)
            error = None if exit_ip else "no exit ip measured"
        except Exception as exc:
            exit_ip, ms = None, None
            error = f"{type(exc).__name__}: {exc}"
        with self._lock:
            self.status["verify"] = {"state": "done", "exit_ip": exit_ip,
                                     "ms": ms, "via_tag": tag,
                                     "error": error}
        self._record_history("verify-done", f"{tag} exit={exit_ip} ms={ms}")

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
            old_proc, self._singbox_proc = self._singbox_proc, None
            old_handle, self._stderr_handle = self._stderr_handle, None
            stderr_path = f"{self.config_path}.stderr.log"
            config_path = self.config_path
            singbox_bin = self.singbox_bin
            try:
                if (os.path.exists(stderr_path)
                        and os.path.getsize(stderr_path) > 200 * 1024):
                    os.unlink(stderr_path)
            except OSError:
                pass
            try:
                new_handle = open(stderr_path, "ab")
            except OSError:
                new_handle = None
            try:
                new_proc = subprocess.Popen(
                    [singbox_bin, "run", "-c", config_path],
                    stdout=subprocess.DEVNULL,
                    stderr=new_handle or subprocess.DEVNULL,
                )
            except OSError as exc:
                print(f"sing-box start failed: {exc}", flush=True)
                new_proc = None
                if new_handle is not None:
                    try:
                        new_handle.close()
                    except OSError:
                        pass
                    new_handle = None
            self._singbox_proc = new_proc
            self._stderr_handle = new_handle
        # Reap outside the lock; the supervise loop retries a dead proc
        # with backoff, so a failed spawn is recovered, not fatal.
        _reap_process(old_proc, old_handle)

    def _terminate_singbox(self) -> None:
        with self._lock:
            proc, self._singbox_proc = self._singbox_proc, None
            handle, self._stderr_handle = self._stderr_handle, None
        _reap_process(proc, handle)

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
                new_proc = subprocess.Popen(
                    [binary, "tunnel", "--protocol", "quic", "--no-autoupdate",
                     "run", "--token", self.tunnel_token],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except OSError as exc:
                self.status["tunnel"] = {"state": "dead", "error": str(exc)}
                return False
            old_proc, self._cloudflared_proc = self._cloudflared_proc, new_proc
            self.status["tunnel"] = {"state": "running", "since": _now_iso()}
            print("cloudflared tunnel started", flush=True)
        _reap_process(old_proc)
        return True

    def _terminate_cloudflared(self) -> None:
        with self._lock:
            proc, self._cloudflared_proc = self._cloudflared_proc, None
            self.status["tunnel"] = {"state": "off"}
        _reap_process(proc)

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
        dial_workers=cfg["dial_workers"],
        vless_uuid=cfg["vless_uuid"],
        vless_direct_port=cfg["vless_direct_port"],
        vless_chain_port=cfg["vless_chain_port"],
        tunnel_token=cfg["tunnel_token"],
        cloudflared_bin=cfg["cloudflared_bin"],
        disguise_path=cfg["disguise_path"],
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
