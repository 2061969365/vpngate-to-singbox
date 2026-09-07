# vpngate-to-singbox

VPNGate `.ovpn` (TCP) → sing-box `openvpn-client` endpoint 转换器，附带 Railway 部署入口。

核心结论（已实测）：sing-box ≥ 1.14 的 `openvpn-client` 用 `system: false`
走内部协议栈，**免 TUN、免 NET_ADMIN**，普通容器里就能拨 VPNGate 出站
（Action `live-dial` 实测：runner 直连 `20.168.111.83` → 经 VPNGate 出口
`219.100.37.244`；`live-stability` 实测可用节点延迟 ~0.7s、下载 20–47 Mbps）。

## 本地用法

```bash
# 单个 .ovpn
python vpngate_to_singbox.py --input node.ovpn --output singbox.json --tag vpngate-0
# 真实快照批量（只留 TCP，按 Speed 排序取 Top N）
python vpngate_to_singbox.py --csv vpngate.csv --limit 8 --output singbox.json --tag vpngate
# 附带 mixed 入站（拨测用）
python vpngate_to_singbox.py --csv vpngate.csv --limit 3 --output dial.json \
  --tag vpngate --mixed 127.0.0.1:18080
```

## Railway 部署

`railway_manager.py` 独占 `$PORT` 做首字节分流，单端口同时服务：

| 流量 | 判定 | 去向 |
|---|---|---|
| `0x05...` | SOCKS5 | 下游 sing-box `mixed`（127.0.0.1:40000） |
| `CONNECT ...` | HTTP 代理 | 下游 sing-box `mixed` |
| `GET /healthz` | 健康检查 | `200 ok`（优先） |
| `GET /ui`、`GET /api/status` | 管理页 | 节点列表 / JSON 状态 |
| 其他 | — | 直接关闭 |

快照每 20 分钟（`REFRESH_SECONDS`）重拉，失败保留旧配置；sing-box 异常退出会被看门狗记到 `/api/status`。

### 部署步骤（Dashboard）

1. 新建 Railway service → 从本仓库部署（`railway.toml` 已指定 `Dockerfile.railway`）。
2. Region 建议选新加坡（离 VPNGate 亚洲节点近）。
3. Variables：`PROXY_USER`、`PROXY_PASS`（必须改默认值）、可选 `LIMIT`（默认 8）。
4. 默认域名即 Web 入口：`https://<xxx>.up.railway.app/ui`（HTTP ingress 只放行标准 GET/POST，
   所以浏览器管理页走这里）。
5. 再加一个 **TCP Proxy**（Service → Networking → TCP Proxy），目标端口填 `$PORT`
   对应的内部端口 → 得到 `xxx.proxy.rlwy.net:随机端口`，SOCKS5 客户端连这里
   （用户名/密码 = `PROXY_USER`/`PROXY_PASS`）。
6. 健康检查：`railway.toml` 已配 `/healthz`，失败自动重启（最多 10 次）。

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `8080` | Railway 自动注入，必须监听 `0.0.0.0:$PORT` |
| `MIXED_PORT` | `40000` | sing-box mixed 下游端口（仅 127.0.0.1） |
| `PROXY_USER` / `PROXY_PASS` | `u` / `p` | 代理认证，生产必须改 |
| `SNAPSHOT_URL` | VPNGate 官方 API | 快照源 |
| `REFRESH_SECONDS` | `1200` | 快照刷新间隔 |
| `LIMIT` | `8` | 每次取 Top N 个 TCP 节点 |

### 合规警告

Railway AUP 明文禁止 proxy / anonymization 服务，本部署仅适合临时演示调试，
长期跑有封号风险。VPNGate 是志愿者学术网络，节点小时级更替、质量波动大，
生产出站请用正经 VPS。
