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
# 真实快照批量：全量拉取，只留 TCP 握得通的节点，按实测延迟排序
python vpngate_to_singbox.py --csv vpngate.csv --output singbox.json --tag vpngate
# 限制数量 + 对 Top-K 做隧道内真实端到端延迟实测并优先排序
python vpngate_to_singbox.py --csv vpngate.csv --limit 8 --real-topk 5 \
  --output singbox.json --tag vpngate
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
| `GET /healthz` | 健康检查 | 有可用节点且 sing-box 存活 → `200 ok`，否则 `503` |
| `GET /ui` | 管理页外壳 | 无鉴权（不含数据，首次打开会提示输入 token） |
| `GET /api/status` 等 | 数据/操作 | 需要 `Authorization: Bearer $ADMIN_TOKEN`，否则 `401` |
| 其他 | — | 直接关闭 |

出站默认走 `auto`（urltest 每分钟优选，`direct` 兜底不断网）；也可在 `/ui`
按国家下拉手动 `Switch`  pin 住某个节点。被 pin 的节点由健康监控每分钟
TCP 复检，连续 3 次不通自动解 pin 回 `auto`。

快照每 20 分钟（`REFRESH_SECONDS`）重拉：先实测 TCP 延迟过滤、只留握得通的，
再对 Top-K（`REAL_TOPK`）做隧道内真实端到端延迟实测并优先排序；
新配置先过 `sing-box check` 才原子落盘（`600` 权限）并重启，失败保旧
（内存中的旧节点 + 磁盘 `last-good` 文件，无快照缓存兜底）；
启动时优先秒装磁盘上的 `last-good`（秒级恢复 `/healthz 200`），再后台重拉新快照。
sing-box 异常退出按 5/10/20/40/300s 退避自愈，连续 5 次等下一轮刷新。

### 部署步骤（Dashboard）

1. 新建 Railway service → 从本仓库部署。注意：`railway.toml`（Config as Code）
   已被官方废弃——2026-08-28 后建的新项目 service 不再读取它，旧 service 也只用到
   2026-12-01 硬下线。所以以 **Dashboard 手填为准**：Service → Settings →
   Builder 选 `DOCKERFILE`、Dockerfile Path 填 `Dockerfile.railway`
  （`railway.toml` 留着给老 service 用；要迁新 IaC 可跑 `railway config migrate`
   生成 `.railway/railway.ts`，不要手写）。
2. Region 建议选新加坡（离 VPNGate 亚洲节点近）。
3. Variables：`PROXY_USER`、`PROXY_PASS`（≥16 位，弱口令直接拒绝启动）、
   `ADMIN_TOKEN`（留空则启动时随机生成并打印到日志，`/ui` 里填一次即可）、
    可选 `LIMIT`（默认 `0` = 全量）、`REAL_TOPK`（默认 `5`，每次刷新实测隧道延迟的节点数）。
4. 默认域名即 Web 入口：`https://<xxx>.up.railway.app/ui`。HTTP ingress 在边缘终结
   TLS，只放行标准 HTTP/1.1、HTTP/2、websocket——SOCKS5 明文握手（`0x05`）和明文
   `CONNECT` 根本到不了容器，所以浏览器管理页走这里，代理流量必须走下面的 TCP Proxy。
5. 再加一个 **TCP Proxy**（Service → Networking → TCP Proxy），目标端口填**数字端口**
   （= `PORT` 环境变量的实际值；没自定义就去看 deploy 日志里的
   `listening on 0.0.0.0:xxxx`，填那个 `xxxx`，**不要填字面 `$PORT`**）→ 得到
   `xxx.proxy.rlwy.net:随机端口`，SOCKS5 客户端连这里
   （用户名/密码 = `PROXY_USER`/`PROXY_PASS`）。
6. 健康检查：部署时 Railway 查 `/healthz`（`200` 才切流量，`healthcheckTimeout` 内无
   `200` 则本次部署标失败）。注意健康检查**只在部署时用**，上线后 `/healthz` 变 `503`
   不会触发重启；`ON_FAILURE + 最多 10 次`只管进程崩溃退出，不管业务状态。
7. 持久化（强烈建议）：挂一个 Volume 到 `/data`，并设 `DATA_DIR=/data`。
   运行时文件（`singbox-railway.json`、`nodes.json`、`state.json`、上次可用配置）
   默认落工作目录，重部署即丢；指向 volume 后启动秒装 `last-good`、`/healthz` 秒变
   `200`。**没有 volume 的全新部署**只能等首次完整刷新（拉快照 + 全量 TCP 探活 +
   `REAL_TOPK` 隧道实测，分钟级），期间 `/healthz` 一直 `503`，可能超过
   `healthcheckTimeout`（默认 300s）导致部署失败——这种失败重试一次通常就过
   （节点已部分就绪），或临时把 `REAL_TOPK=0` 加速首次启动。

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `8080` | Railway 自动注入，必须监听 `0.0.0.0:$PORT` |
| `MIXED_PORT` | `40000` | sing-box mixed 下游端口（仅 127.0.0.1） |
| `PROXY_USER` / `PROXY_PASS` | `u` / `p` | 代理认证；`PROXY_PASS` 不足 16 位直接拒绝启动 |
| `ADMIN_TOKEN` | （随机生成） | `/api/*` 的 Bearer token（`/ui` 外壳本身无鉴权，打开后在页面里填 token，用于浏览器调用 `/api/*`）；不足 16 位则自动生成并打印到日志 |
| `SNAPSHOT_URL` | VPNGate 官方 API | 快照源，必须是 `https` |
| `REFRESH_SECONDS` | `1200` | 快照刷新间隔；连续失败 ≥3 次后间隔减半（默认 1200→600s），下限 300s |
| `LIMIT` | `0` | `0` = 全量拉取握得通的 TCP 节点；>0 则只留 Top N（实测延迟排序） |
| `REAL_TOPK` | `5` | 每次刷新对握手最快的前 K 个节点做隧道内真实延迟实测并优先排序 |
| `DATA_DIR` | `.` | 运行时文件目录；Railway 挂 volume 到 `/data` 时设为 `/data` |

### API（`/ui`、`/`、`GET /healthz` 无需 token；`/api/*` 需 `Authorization: Bearer $ADMIN_TOKEN`）

| 方法与路径 | 说明 |
|---|---|
| `GET /healthz` | 存活检查：有节点且 sing-box 存活 → `200 ok`，否则 `503` |
| `GET /api/status` | JSON：节点（含国家/延迟/存活时长）、`countries`、`preferred_tag`、`refresh_history`、`refresh_ok/fail`、`uptime_seconds`、流量计数 |
| `POST /api/switch` | `{"country":"JP"}` 按国家切最低延迟节点；`{"tag":"vpngate-3"}` pin 指定节点；`{"tag":"auto"}` 回自动 |
| `POST /api/refresh` | 立即重拉快照并重载 |

### 稳定性历史

`live-stability` 每小时拨测（6 轮延迟 + 10MB 下载），原始 `probe.jsonl`
留存 90 天（artifact），汇总行追加到 `data` 分支的 `history.jsonl`；
gate 变红自动开/追评 Tracking Issue（`stability-tracking` 标签）。

### 合规警告

Railway AUP 明文禁止 proxy / anonymization 服务，本部署仅适合临时演示调试，
长期跑有封号风险。VPNGate 是志愿者学术网络，节点小时级更替、质量波动大，
生产出站请用正经 VPS。
