# 演示入口与操作手册（Runbook）

本文件是本项目的演示入口，汇总“怎么启动、看什么、如何验证关键保证”。
交互式 API 文档由 FastAPI 提供：服务启动后访问 `http://127.0.0.1:8000/docs`。

## 1. 一键启动（Docker Compose）

前置：已安装 Docker 与 Compose v2。

```bash
docker compose up -d --build
# 查看服务状态
docker compose ps
# 跟随探测服务日志
docker compose logs -f probe
```

启动后涉及四个服务：

| 服务 | 地址/端口 | 作用 |
| --- | --- | --- |
| `certinit` | 一次性任务 | 生成演示 CA、服务器证书、合并 CA bundle |
| `dns-service` | 172.31.0.53，UDP/53 + HTTP/8053 | 本地可热切换 profile 的解析器 |
| `target-allowed` | 172.31.10.10，HTTP 80/8080、HTTPS 443/8443、**不回应 TLS 关闭 9443** | 允许网段演示目标 |
| `target-forbidden` | 172.31.20.10 | 禁止网段目标（白名单拦截，零请求到达） |
| `probe` | 宿主机 `127.0.0.1:8000` | 出站探测 API（`/docs`、`/healthz`） |

停止与清理：

```bash
docker compose down            # 停止并移除容器/网络
docker compose down -v         # 连同证书/状态卷一起清理
```

## 2. 交互式文档与辅助接口

- Swagger UI：<http://127.0.0.1:8000/docs>
- OpenAPI Schema：<http://127.0.0.1:8000/openapi.json>
- 健康检查：`GET http://127.0.0.1:8000/healthz`
- 当前策略与超时：`GET http://127.0.0.1:8000/api/v1/policy`

## 3. 一键演示脚本

```bash
./scripts/demo.sh
```

脚本依次演示：允许目标（HTTP/HTTPS）、禁止目标拦截、检查后换址、混合解析
整体拒绝、跳转各类边界、**不回应 TLS 关闭目标的有界收尾**、IPv4-only 与
入口校验，并最后核对禁止目标从未收到探测请求。

## 4. 本次修复重点：探测截止与连接收尾

### 4.1 背景问题

- 运维连续检查 HTTPS 回调时，若目标不回应 TLS `close_notify`，旧连接会
  停留在关闭等待中（Python 3.11 内置 SSL 关闭超时约 30s），持续占用；
- 若总超时发生在“读取响应”阶段，原先外层 `wait_for` 取消后，连接收尾在
  `finally` 里无界等待，请求与并发名额迟迟不释放；
- 旧实现读取响应体忽略 `Content-Length`、只等对端关闭，于是“响应正常但
  不关闭连接”的目标会把已取得的 200 结论误判成读取超时。

### 4.2 修复后的保证

1. **收尾计入既有总时限**：每次探测有一个贯穿 DNS/TCP/TLS/读取/收尾的
   绝对截止时间（`deadline`），所有阶段取“阶段超时”与“剩余总时限”的较小值。
2. **返回结果、归还名额前连接与通信任务全部退出**：每条连接都经
   `shutdown_writer()` 有界收尾——优雅关闭超时或总时限已到时，直接
   `transport.abort()` 强制回收，再以固定小上限等待退出。
3. **连续超时不积累旧连接**：回归测试以 8 次连续探测验证客户端 fd 数
   与任务数不随探测次数增长。
4. **已取得结论不因关闭等待改报**：响应按 `Content-Length` 读完即确定
   结论；收尾只释放资源，成功仍返回成功。
5. **真正超时仍返回 408**：总时限到达抛 `DeadlineReached`，API 转 408 并
   附带超时前已完成的逐跳信息；单阶段读取超时仍是跳内 `error`，不混淆。
6. **满额拒收/健康检查/正常探测不受影响**：满额立即 429；`/healthz`
   恒可用；有空余名额时正常探测路径不变。
7. **安全模型不回退**：逐跳 CIDR 全或无校验、仅在已批准地址内重试、
   HTTPS 始终按原域名 SNI 与校验证书（无关闭开关）。

新增配置项：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `CLOSE_TIMEOUT` | 2.0 秒 | 单条连接优雅关闭等待上限；超时即强制 abort |

### 4.3 手动验证“不回应 TLS 关闭”目标

该目标（`target-allowed` 容器内 9443 端口）完成 TLS 握手、返回带
`Content-Length` 的 200 后保持连接，既不主动关闭也不回应 `close_notify`。

```bash
# DNS profile 中 noclose.allowed.demo.test -> 172.31.10.10
curl -sS -X POST http://127.0.0.1:8000/api/v1/probe \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://noclose.allowed.demo.test:9443/"}' | jq .
```

预期：`outcome=ok`、最终跳 `status_code=200`，且整个请求在约
`CLOSE_TIMEOUT` 量级内返回（而不是 30s 级卡顿或超时）。连续多次调用，
探测服务的并发名额与 fd 都不会被旧连接占满。

### 4.4 手动验证总超时 408 与名额释放

将探测服务 `PROBE_OVERALL_TIMEOUT` 调小（例如 2s），探测一个接受请求但
不返回响应的目标，应得到 HTTP 408，`detail.hops` 内含已发出请求的跳信息；
408 返回后立刻探测正常目标，应立即成功（证明名额已释放）。

## 5. DNS profile 热切换

```bash
curl http://127.0.0.1:8053/profiles
curl -X POST http://127.0.0.1:8053/profiles/switch \
  -H 'Content-Type: application/json' -d '{"profile":"swapped"}'
```

| profile | 演示点 |
| --- | --- |
| `allowed` | 正常解析到允许网段（含 `noclose.allowed.demo.test`） |
| `swapped` | 同名域名换到禁止地址（DNS rebinding） |
| `mixed` | 一次应答含允许与禁止地址，整体拒绝 |
| `loop` | 连环 307 跳转，验证 3 次上限 |

## 6. 本地测试

```bash
pip install -r requirements.txt pytest pytest-asyncio httpx
pytest -q
```

回归测试 `tests/test_deadline_teardown.py` 专门覆盖：有界收尾与强制 abort、
连接/任务不积累、总时限 408、单阶段超时仍为跳内错误、`Content-Length`
读取，以及 CIDR/重试/证书校验等安全特性不回退。
