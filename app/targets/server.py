"""演示用目标 Web 服务。

同一进程监听：
* 8080/tcp HTTP（允许目标 172.31.10.10 与禁止目标 172.31.20.10 都运行本服务）；
* 8443/tcp HTTPS（使用受信演示 CA 签发的证书，含全部演示域名 SAN）。

按 Host 头提供不同路径行为：正常 200、跳转至允许/禁止目标、跳转链、
回显请求来源等。``/_requests`` 记录本进程收到的请求，供演示脚本验证
“被策略拒绝的目标从未收到探测请求”。

此外提供一个独立的 *不回应 TLS 关闭* 的原始 TLS 监听
（``TLS_NO_CLOSE_PORT``，默认 9443）：正常完成 TLS 握手并返回带
Content-Length 的 200 响应，之后保持连接、既不主动关闭也不回应
close_notify，用于复现与回归验证“探测端收尾必须有界、旧连接不得
积累、已取得结论不得被改报超时”。
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import threading
import time
from collections import deque

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

CERT_DIR = os.getenv("CERT_DIR", "/app/certs")
# 不回应 TLS 关闭的演示目标端口（仅容器网络内可达，不对外发布）
TLS_NO_CLOSE_PORT = int(os.getenv("TLS_NO_CLOSE_PORT", "9443"))
# 保持悬挂连接的最长时间（秒）：到期后服务端自行放弃该连接，
# 避免演示长期运行时 fd 无限增长；探测端应早已在 close_timeout 内 abort。
SILENT_HOLD_SECONDS = float(os.getenv("TLS_NO_CLOSE_HOLD", "300"))
RECENT_REQUESTS: deque[dict] = deque(maxlen=200)

app = FastAPI(title="demo-targets", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def record_requests(request: Request, call_next):
    RECENT_REQUESTS.appendleft(
        {
            "ts": round(time.time(), 3),
            "method": request.method,
            "host": request.headers.get("host"),
            "path": request.url.path,
            "peer": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
    )
    return await call_next(request)


@app.get("/")
async def root(request: Request):
    return JSONResponse(
        {
            "service": "demo-targets",
            "host": request.headers.get("host"),
            "peer": request.client.host if request.client else None,
            "tls": request.url.scheme == "https",
            "message": "目标可达",
        }
    )


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.get("/_requests")
async def list_requests():
    return JSONResponse(list(RECENT_REQUESTS))


@app.get("/redirect-allowed")
async def redirect_allowed():
    return RedirectResponse(url="http://redirect-final.demo.test/final", status_code=302)


@app.get("/redirect-https")
async def redirect_https():
    return RedirectResponse(
        url="https://https.allowed.demo.test/secure", status_code=302
    )


@app.get("/redirect-forbidden")
async def redirect_forbidden():
    # 跳到禁止网段的目标：探测方必须在第二跳解析校验时拦截
    return RedirectResponse(url="http://forbidden.demo.test/secret", status_code=302)


@app.get("/redirect-scheme")
async def redirect_scheme():
    # 跳到非 HTTP(S) 协议：探测方应拒绝
    return RedirectResponse(url="file:///etc/passwd", status_code=302)


@app.get("/final")
async def final():
    return JSONResponse({"message": "跳转链终点，可达"})


@app.get("/secure")
async def secure(request: Request):
    return JSONResponse(
        {
            "message": "HTTPS 目标可达，证书按原域名验证通过",
            "host": request.headers.get("host"),
            "scheme": request.url.scheme,
        }
    )


# 跳转链：loop1/loop/1 -> loop2/loop/2 -> loop3/loop/3 -> loop4/loop/4 -> loop1 …
@app.get("/loop/{n}")
async def loop_chain(n: int):
    next_n = 1 if n >= 4 else n + 1
    return RedirectResponse(
        url=f"http://loop{next_n}.demo.test/loop/{next_n}",
        status_code=307,
    )


@app.get("/secret")
async def secret():
    return JSONResponse({"message": "禁止网段目标不应被任何探测请求到达"})


def _server_kwargs() -> dict:
    return {
        "app": app,
        "log_level": "warning",
        "access_log": False,
    }


async def _one_server(port: int, ssl_cert: str | None = None,
                      ssl_key: str | None = None) -> uvicorn.Server:
    cfg_kwargs = dict(host="0.0.0.0", port=port, **_server_kwargs())
    if ssl_cert and ssl_key:
        cfg_kwargs.update(ssl_certfile=ssl_cert, ssl_keyfile=ssl_key)
    server = uvicorn.Server(uvicorn.Config(**cfg_kwargs))
    # 直接返回由 gather 驱动；这里只构造，不阻塞
    return server


# ------------------------------------------------- 不回应 TLS 关闭的演示目标
def _raw_no_close_connection(conn: socket.socket, cert: str, key: str) -> None:
    """在独立线程中处理一条“不回应 TLS 关闭”的连接。

    使用原生 socket + ``ssl.wrap_socket`` 而非 asyncio SSL 传输：后者在
    收到对端 close_notify 时会自动回送关闭并结束连接，无法模拟“目标不
    回应 TLS 关闭”。这里完成握手、返回带 Content-Length 的 200 后，既不
    ``unwrap`` 也不 ``shutdown``，一直持有到上限，从而真实复现运维场景。
    """
    tls_sock: ssl.SSLSocket | None = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        tls_sock = ctx.wrap_socket(conn, server_side=True)
        tls_sock.settimeout(max(SILENT_HOLD_SECONDS + 5.0, 10.0))
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = tls_sock.recv(4096)
            if not chunk:
                return
            data += chunk
        body = b'{"message":"no-tls-close target: responded, will not close"}'
        head = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: keep-alive\r\n\r\n" + body
        )
        tls_sock.sendall(head)
        # 关键：不调用 unwrap()/shutdown()，持有连接到上限。
        # 对端（探测端）发 close_notify 也得不到回应，只能自行超时 abort。
        time.sleep(SILENT_HOLD_SECONDS)
    except (OSError, ssl.SSLError, socket.timeout):
        # 对端强制 abort 会在此体现，属预期
        pass
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        else:
            try:
                conn.close()
            except OSError:
                pass


class _RawTlsNoCloseServer:
    """在线程中 accept 的原始 TLS 监听（不回应关闭）。"""

    def __init__(self, port: int, cert: str, key: str) -> None:
        self._port = port
        self._cert = cert
        self._key = key
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._server_sock: socket.socket | None = None

    def _serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self._port))
        sock.listen(128)
        sock.settimeout(0.5)
        self._server_sock = sock
        while not self._stop.is_set():
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=_raw_no_close_connection,
                args=(conn, self._cert, self._key),
                daemon=True,
            ).start()
        sock.close()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._serve, name="tls-no-close", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def _serve_tls_no_close(cert: str, key: str) -> _RawTlsNoCloseServer:
    server = _RawTlsNoCloseServer(TLS_NO_CLOSE_PORT, cert, key)
    server.start()
    print(
        f"[demo-targets] 不回应 TLS 关闭的目标已监听 0.0.0.0:{TLS_NO_CLOSE_PORT}"
        f"（保持连接最长 {SILENT_HOLD_SECONDS:.0f}s）",
        flush=True,
    )
    return server


async def serve() -> None:
    # 同时监听标准端口（80/443，供跳转 URL 直接使用）与演示端口（8080/8443）。
    # 容器以 root 启动可绑定特权端口；本地非特权演示可经环境变量改为高位端口。
    http_ports = [int(p) for p in os.getenv("TARGET_HTTP_PORTS", "80,8080").split(",")]
    https_ports = [int(p) for p in os.getenv("TARGET_HTTPS_PORTS", "443,8443").split(",")]
    cert = f"{CERT_DIR}/targets.fullchain.pem"
    key = f"{CERT_DIR}/targets.key.pem"
    servers: list[uvicorn.Server] = []
    for p in http_ports:
        servers.append(await _one_server(p))
    for p in https_ports:
        servers.append(await _one_server(p, cert, key))
    no_close_server = _serve_tls_no_close(cert, key)
    try:
        await asyncio.gather(*(s.serve() for s in servers))
    finally:
        # 原始 TLS 监听运行在独立线程，停止其 accept 循环
        no_close_server.stop()


if __name__ == "__main__":
    asyncio.run(serve())
