"""FastAPI 接口层测试。

TestClient 会在独立线程的独立事件循环中运行应用，因此所有本地假服务
（DNS/UDP、HTTP/TCP）都通过应用的 lifespan 钩子在 *同一* 循环内创建。
"""

from __future__ import annotations

import asyncio
import importlib
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from app.probe import dns_wire


class InLoopDns:
    def __init__(self) -> None:
        self.zones: dict[str, list[str]] = {}
        self._transport = None

    def connection_made(self, transport):  # noqa: ANN001
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        msg = dns_wire.parse_message(data, require_qr=False)
        q = msg.questions[0]
        if q.qname.lower() in self.zones:
            reply = dns_wire.build_response(msg.qid, q, answers=self.zones[q.qname.lower()])
        else:
            reply = dns_wire.build_response(
                msg.qid, q, rcode=dns_wire.RCODE_NAME_ERROR
            )
        self._transport.sendto(reply, addr)


class InLoopHttp:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], tuple[int, dict, str]] = {}
        self.requests: list[dict] = []
        self._server = None
        self.port = 0

    def route(self, host, path, status=200, headers=None, body="ok"):  # noqa: ANN001
        self.routes[(host.lower(), path)] = (status, headers or {}, body)

    async def _handle(self, reader, writer):  # noqa: ANN001
        try:
            line = await reader.readline()
            if not line:
                return
            method, path, _ = line.decode().split(" ", 2)
            headers = {}
            while True:
                h = await reader.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                k, v = h.decode().split(":", 1)
                headers[k.strip().lower()] = v.strip()
            host = headers.get("host", "").split(":")[0].lower()
            self.requests.append({"method": method, "host": host, "path": path})
            status, extra, body = self.routes.get((host, path), (404, {}, "nf"))
            head = [
                f"HTTP/1.1 {status} X\r\n",
                f"Content-Length: {len(body)}\r\n",
                "Connection: close\r\n",
            ]
            for k, v in extra.items():
                head.append(f"{k}: {v}\r\n")
            head.append("\r\n")
            head.append(body)
            writer.write("".join(head).encode())
            await writer.drain()
        except (ConnectionError, ValueError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()


@pytest.fixture()
def client(monkeypatch, demo_certs):
    _cert, _key, cafile = demo_certs
    dns = InLoopDns()
    httpd = InLoopHttp()

    import app.probe.main as main_mod

    @asynccontextmanager
    async def test_lifespan(app):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: dns, local_addr=("127.0.0.1", 0)
        )
        dns._transport = transport
        dns_port = transport.get_extra_info("socket").getsockname()[1]
        await httpd.start()

        monkeypatch.setenv("ALLOWED_CIDRS", "127.0.0.1/32")
        monkeypatch.setenv("DNS_SERVER", "127.0.0.1")
        monkeypatch.setenv("DNS_PORT", str(dns_port))
        monkeypatch.setenv("DNS_RETRIES", "0")
        monkeypatch.setenv("DNS_TIMEOUT", "2.0")
        monkeypatch.setenv("CA_BUNDLE", str(cafile))
        monkeypatch.setenv("CONNECT_TIMEOUT", "3.0")
        monkeypatch.setenv("READ_TIMEOUT", "5.0")
        monkeypatch.setenv("TLS_TIMEOUT", "5.0")
        monkeypatch.setenv("CLOSE_TIMEOUT", "1.0")
        monkeypatch.setenv("PROBE_OVERALL_TIMEOUT", "15.0")

        import app.probe.config as config_mod
        import app.probe.dns_client as dns_client_mod

        importlib.reload(config_mod)
        importlib.reload(dns_client_mod)
        importlib.reload(main_mod)
        main_mod.app.router.lifespan_context = test_lifespan
        try:
            yield
        finally:
            transport.close()
            await httpd.stop()

    main_mod.app.router.lifespan_context = test_lifespan
    dns.zones = {"api-good.test": ["127.0.0.1"]}
    httpd.route("api-good.test", "/")
    with TestClient(main_mod.app) as c:
        c._dns = dns
        c._http = httpd
        yield c


def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_policy_endpoint(client):
    body = client.get("/api/v1/policy").json()
    assert body["allowed_cidrs"] == ["127.0.0.1/32"]
    assert body["ip_versions"] == ["IPv4"]
    assert body["max_redirects"] == 3
    assert body["tls_verify"] is True


def test_probe_ok(client):
    port = client._http.port
    r = client.post("/api/v1/probe", json={"url": f"http://api-good.test:{port}/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "ok"
    assert body["hops"][0]["connected_peer"] == f"127.0.0.1:{port}"
    assert body["hops"][0]["resolved_addresses"] == ["127.0.0.1"]
    assert client._http.requests[-1]["host"] == "api-good.test"


def test_probe_blocked_reports_reason(client):
    client._dns.zones = {"api-bad.test": ["8.8.8.8"]}
    r = client.post("/api/v1/probe", json={"url": "http://api-bad.test/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "blocked"
    assert "白名单" in body["summary"]
    assert body["hops"][-1]["request_sent"] is False
    assert all(req["host"] != "api-bad.test" for req in client._http.requests)


def test_probe_blocked_returns_structured_hop(client):
    client._dns.zones = {"api-mix.test": ["127.0.0.1", "9.9.9.9"]}
    body = client.post(
        "/api/v1/probe", json={"url": "http://api-mix.test/"}
    ).json()
    assert body["outcome"] == "blocked"
    hop = body["hops"][-1]
    assert hop["resolved_addresses"] == ["127.0.0.1", "9.9.9.9"]
    assert hop["approved_addresses"] == []
    assert hop["connected_peer"] is None


def test_probe_invalid_scheme_reported(client):
    # 非法 scheme 在跳内被静态拦截，返回结构化 blocked（不产生流量）
    r = client.post("/api/v1/probe", json={"url": "ftp://api-good.test/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "blocked"
    assert body["hops"][-1]["request_sent"] is False


def test_probe_bad_method_422(client):
    r = client.post(
        "/api/v1/probe",
        json={"url": "http://api-good.test/", "method": "POST"},
    )
    assert r.status_code == 422


def test_openapi_docs_available(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


class _SilentServer:
    """接受连接与请求但永不响应的本地 HTTP 目标（用于总超时 408）。"""

    def __init__(self) -> None:
        self._server = None
        self.port = 0

    async def _handle(self, reader, writer):  # noqa: ANN001
        try:
            await reader.read(4096)
        except OSError:
            pass
        await asyncio.sleep(30)

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()


def test_probe_overall_timeout_returns_408_with_hops(client, monkeypatch):
    # 总超时发生在读取中：必须返回 408，且名额在收尾后释放、可继续正常探测
    import app.probe.main as main_mod

    # Settings 为 frozen dataclass，用 object.__setattr__ 调整测试参数
    object.__setattr__(main_mod.settings, "overall_timeout", 1.0)
    monkeypatch.setattr(main_mod.prober, "_read_timeout", 30.0, raising=False)

    # TestClient 在独立线程/循环跑应用；用其 portal 启动目标服务
    portal = client.portal
    silent = _SilentServer()
    portal.call(silent.start)
    client._dns.zones = {"api-silent.test": ["127.0.0.1"]}
    try:
        t0 = __import__("time").monotonic()
        r = client.post(
            "/api/v1/probe", json={"url": f"http://api-silent.test:{silent.port}/"}
        )
        elapsed = __import__("time").monotonic() - t0
        assert r.status_code == 408
        body = r.json()["detail"]
        assert "总超时" in body["message"]
        assert body["elapsed_ms"] >= 900
        # 408 携带超时前的逐跳信息
        assert body["hops"] and body["hops"][0]["request_sent"] is True
        assert elapsed < 5.0  # 收尾有界，未被悬挂连接拖住
    finally:
        portal.call(silent.stop)


def test_slot_released_after_timeout_followup_probe_works(client, monkeypatch):
    import app.probe.main as main_mod

    object.__setattr__(main_mod.settings, "overall_timeout", 1.0)
    monkeypatch.setattr(main_mod.prober, "_read_timeout", 30.0, raising=False)
    portal = client.portal
    silent = _SilentServer()
    portal.call(silent.start)
    client._dns.zones = {
        "api-silent2.test": ["127.0.0.1"],
        "api-good.test": ["127.0.0.1"],
    }
    try:
        r1 = client.post(
            "/api/v1/probe",
            json={"url": f"http://api-silent2.test:{silent.port}/"},
        )
        assert r1.status_code == 408
        # 名额已随收尾释放：正常探测立即可用
        port = client._http.port
        r2 = client.post(
            "/api/v1/probe", json={"url": f"http://api-good.test:{port}/"}
        )
        assert r2.status_code == 200
        assert r2.json()["outcome"] == "ok"
    finally:
        portal.call(silent.stop)


def test_full_concurrency_rejects_with_429(client, monkeypatch):
    import app.probe.main as main_mod

    # 直接占满信号量，制造满额（不改动 frozen settings）
    sem = main_mod._semaphore
    monkeypatch.setattr(sem, "_value", 0, raising=False)
    r = client.post(
        "/api/v1/probe", json={"url": "http://api-good.test/"}
    )
    assert r.status_code == 429
    assert "并发" in r.json()["detail"]


def test_healthz_always_available(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/healthz").json()["status"] == "ok"


def test_policy_reports_close_timeout(client):
    body = client.get("/api/v1/policy").json()
    assert "close" in body["timeouts"]
    assert body["timeouts"]["overall"] > 0
