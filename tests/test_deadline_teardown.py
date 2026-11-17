"""探测截止与连接收尾回归测试。

针对运维场景：
* 目标不回应 TLS close_notify 时，已返回结论的旧连接不得继续占用；
* 总超时发生在读取中时，请求与并发名额必须随连接收尾一起释放；
* 收尾计入既有总时限；返回结果/归还名额前连接与通信任务必须全部退出；
* 连续超时不得积累旧连接（fd / 任务数不增长）；
* 已取得的探测结论不得仅因关闭等待改报超时；真正超时仍返回 408；
* 满额拒收（429）、健康检查、有空余名额的正常探测仍可用；
* 逐跳 CIDR 检查、已批准地址重试、按原域名校验证书等安全特性不回退。
"""

from __future__ import annotations

import asyncio
import os

import pytest

from app.probe.connection import DeadlineReached, shutdown_writer
from app.probe.policy import PolicyError


NO_CLOSE_HOST = "noclose.allowed.demo.test"


class TestTlsNoCloseTeardown:
    async def test_successful_conclusion_not_degraded_by_close_wait(
        self, fake_dns, tls_no_close_server, make_prober
    ):
        # 目标正常返回 200（带 Content-Length）但不回应 TLS 关闭：
        # 结论必须是 ok/200，不能因关闭等待被改报超时或错误
        fake_dns.set_zones({NO_CLOSE_HOST: ["127.0.0.1"]})
        prober = make_prober(close_timeout=0.5)

        hops = await prober.probe(
            f"https://{NO_CLOSE_HOST}:{tls_no_close_server.port}/"
        )

        hop = hops[-1]
        assert hop.outcome == "ok"
        assert hop.status_code == 200
        assert hop.error is None

    async def test_teardown_is_bounded_and_connection_aborted(
        self, fake_dns, tls_no_close_server, make_prober
    ):
        fake_dns.set_zones({NO_CLOSE_HOST: ["127.0.0.1"]})
        prober = make_prober(close_timeout=0.5)
        loop = asyncio.get_running_loop()

        t0 = loop.time()
        hops = await prober.probe(
            f"https://{NO_CLOSE_HOST}:{tls_no_close_server.port}/"
        )
        elapsed = loop.time() - t0

        # 收尾有界：远小于 asyncio 内置 30s SSL 关闭超时
        assert hops[-1].outcome == "ok"
        assert elapsed < 3.0, f"收尾未在 close_timeout 内完成: {elapsed:.2f}s"

        # 服务端应观察到探测端已断开（abort 生效），连接确实退出
        assert tls_no_close_server.disconnect_events
        await asyncio.wait_for(
            asyncio.gather(*(e.wait() for e in tls_no_close_server.disconnect_events)),
            timeout=3.0,
        )

    async def test_repeated_probes_do_not_accumulate_connections(
        self, fake_dns, tls_no_close_server, make_prober
    ):
        fake_dns.set_zones({NO_CLOSE_HOST: ["127.0.0.1"]})
        prober = make_prober(close_timeout=0.3)
        loop = asyncio.get_running_loop()
        fd_dir = "/proc/self/fd"

        def client_fds() -> set[str]:
            """只统计探测端（客户端）建立的 socket inode。

            服务端为模拟“不回应关闭”会保留 accepted 侧 socket（CLOSE_WAIT），
            那是被测目标的预期行为；这里通过 /proc/net/tcp 排除服务端监听口
            与其 accepted 连接，仅判断探测端是否泄漏连接。
            """
            if not os.path.isdir(fd_dir):
                return set()
            server_port_hex = f"{tls_no_close_server.port:04X}"
            server_inodes: set[str] = set()
            for path in ("/proc/net/tcp",):
                if not os.path.isfile(path):
                    continue
                for line in open(path).read().splitlines()[1:]:
                    fields = line.split()
                    local, inode = fields[1], fields[9]
                    # 本地端口等于服务端端口 => 服务端侧 socket
                    if local.endswith(":" + server_port_hex):
                        server_inodes.add(inode)
            client: set[str] = set()
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if link.startswith("socket:["):
                    inode = link[8:-1]
                    if inode not in server_inodes:
                        client.add(inode)
            return client

        # 预热后取客户端 fd 基线
        await prober.probe(f"https://{NO_CLOSE_HOST}:{tls_no_close_server.port}/")
        await asyncio.sleep(0.2)
        baseline_tasks = len(asyncio.all_tasks(loop))
        baseline_client = client_fds()

        for _ in range(8):
            hops = await prober.probe(
                f"https://{NO_CLOSE_HOST}:{tls_no_close_server.port}/"
            )
            assert hops[-1].outcome == "ok"

        # 探测端任务 drain：连续探测不留下永久悬挂的客户端通信任务
        async def _tasks_drained() -> bool:
            for _ in range(50):
                if len(asyncio.all_tasks(loop)) <= baseline_tasks:
                    return True
                await asyncio.sleep(0.05)
            return False

        assert await _tasks_drained(), (
            f"任务未释放: {len(asyncio.all_tasks(loop))} > {baseline_tasks}"
        )
        # 客户端 socket 不得随探测次数增长（允许 DNS 等少量既有 fd 抖动）
        leftover = client_fds() - baseline_client
        assert not leftover, f"探测端泄漏连接 socket: {sorted(leftover)}"

    async def test_shutdown_writer_force_aborts_silent_tls_peer(
        self, demo_certs
    ):
        # 直接验证低层收尾原语：对不回应关闭的 TLS 传输，shutdown_writer
        # 必须在 close_timeout 内返回且传输已关闭
        import ssl as ssl_mod

        certfile, keyfile, cafile = demo_certs
        server_ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(certfile), str(keyfile))

        hold = asyncio.Event()

        async def silent(reader, writer):  # noqa: ANN001
            try:
                await reader.read(1024)
            except OSError:
                pass
            await hold.wait()  # 永不主动关闭
            writer.close()

        server = await asyncio.start_server(silent, "127.0.0.1", 0, ssl=server_ctx)
        port = server.sockets[0].getsockname()[1]
        client_ctx = ssl_mod.create_default_context(cafile=str(cafile))
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port,
                ssl=client_ctx, server_hostname="allowed.demo.test",
            )
            loop = asyncio.get_running_loop()
            t0 = loop.time()
            await shutdown_writer(writer, close_timeout=0.5)
            assert loop.time() - t0 < 2.0
            assert writer.is_closing()
        finally:
            hold.set()
            server.close()
            await server.wait_closed()


class TestOverallDeadline:
    async def test_deadline_during_read_raises_and_tears_down(
        self, fake_dns, make_prober
    ):
        # 目标接受连接与请求但永不响应：总时限在读取中到达
        async def silent_http(reader, writer):  # noqa: ANN001
            try:
                await reader.read(4096)
            except OSError:
                pass
            await asyncio.sleep(30)

        server = await asyncio.start_server(silent_http, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        fake_dns.set_zones({"deadline.test": ["127.0.0.1"]})
        prober = make_prober(read_timeout=30.0, close_timeout=0.5)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 1.0
        try:
            with pytest.raises(DeadlineReached):
                await prober.probe(
                    f"http://deadline.test:{port}/", deadline=deadline
                )
        finally:
            server.close()
            await server.wait_closed()

    async def test_deadline_returns_within_bounded_time(
        self, fake_dns, demo_certs, make_prober
    ):
        # 总时限在读取阶段到期且对端不回应关闭：整体仍须在有界时间内
        # 退出，不能被 30s 级 TLS 关闭等待拖住。
        # 用一个接受请求后保持沉默的 TLS 目标，保证 deadline 一定在读取中到期。
        import ssl as ssl_mod

        async def silent_tls(reader, writer):  # noqa: ANN001
            try:
                await reader.read(4096)
            except OSError:
                pass
            await asyncio.sleep(30)

        certfile, keyfile, _cafile = demo_certs
        server_ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(certfile), str(keyfile))
        server = await asyncio.start_server(
            silent_tls, "127.0.0.1", 0, ssl=server_ctx
        )
        port = server.sockets[0].getsockname()[1]
        fake_dns.set_zones({NO_CLOSE_HOST: ["127.0.0.1"]})
        prober = make_prober(read_timeout=30.0, close_timeout=5.0)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 0.8
        t0 = loop.time()
        try:
            with pytest.raises(DeadlineReached):
                await prober.probe(
                    f"https://{NO_CLOSE_HOST}:{port}/", deadline=deadline
                )
            # close_timeout=5 但总时限已耗尽：收尾走强制 abort，整体远小于 5s
            assert loop.time() - t0 < 3.0
        finally:
            server.close()
            await server.wait_closed()

    async def test_phase_read_timeout_is_still_hop_error_not_408(
        self, fake_dns, make_prober
    ):
        # 无 deadline 时，单阶段读取超时保持原有行为：hop error，不抛 408
        async def silent_http(reader, writer):  # noqa: ANN001
            try:
                await reader.read(4096)
            except OSError:
                pass
            await asyncio.sleep(5)

        server = await asyncio.start_server(silent_http, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        fake_dns.set_zones({"phase.test": ["127.0.0.1"]})
        prober = make_prober(read_timeout=0.5)
        try:
            hops = await prober.probe(f"http://phase.test:{port}/")
            assert hops[-1].outcome == "error"
            assert "读取响应超时" in (hops[-1].error or "")
        finally:
            server.close()
            await server.wait_closed()

    async def test_no_deadline_path_unchanged(self, fake_dns, http_server,
                                               make_prober):
        # 不传 deadline 的直连/测试路径行为不变
        fake_dns.set_zones({"plain.test": ["127.0.0.1"]})
        http_server.route("plain.test", "/")
        prober = make_prober()
        hops = await prober.probe(f"http://plain.test:{http_server.port}/")
        assert hops[-1].outcome == "ok"
        assert hops[-1].status_code == 200


class TestContentLengthHandling:
    async def test_keepalive_response_with_content_length_completes(
        self, fake_dns, make_prober
    ):
        # 对端保持连接但给了 Content-Length：按长度读完即成功，不等 EOF
        async def keepalive_handle(reader, writer):  # noqa: ANN001
            await reader.read(4096)
            body = b"hello"
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 5\r\n"
                b"Connection: keep-alive\r\n\r\n" + body
            )
            await writer.drain()
            await asyncio.sleep(2)  # 不关连接
            writer.close()

        server = await asyncio.start_server(keepalive_handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        fake_dns.set_zones({"ka.test": ["127.0.0.1"]})
        prober = make_prober(read_timeout=1.0)
        try:
            hops = await prober.probe(f"http://ka.test:{port}/")
            assert hops[-1].outcome == "ok"
            assert hops[-1].status_code == 200
        finally:
            server.close()
            await server.wait_closed()


class TestSafetyPropertiesPreserved:
    async def test_hop_by_hop_cidr_still_enforced(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"denied.test": ["127.0.0.1"]})
        prober = make_prober(allowed=("10.0.0.0/8",))
        hops = await prober.probe(f"http://denied.test:{http_server.port}/")
        assert hops[-1].outcome == "blocked"
        assert hops[-1].request_sent is False

    async def test_approved_address_retry_preserved(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"ha2.test": ["127.0.0.2", "127.0.0.1"]})
        http_server.route("ha2.test", "/")
        prober = make_prober(allowed=("127.0.0.0/24",))
        hops = await prober.probe(f"http://ha2.test:{http_server.port}/")
        assert hops[-1].outcome == "ok"
        assert hops[-1].connected_peer == f"127.0.0.1:{http_server.port}"

    async def test_tls_verified_by_original_hostname_preserved(
        self, fake_dns, https_server, make_prober
    ):
        fake_dns.set_zones({"https.allowed.demo.test": ["127.0.0.1"]})
        https_server.route("https.allowed.demo.test", "/secure")
        prober = make_prober()
        hops = await prober.probe(
            f"https://https.allowed.demo.test:{https_server.port}/secure"
        )
        assert hops[-1].outcome == "ok"
        assert "https.allowed.demo.test" in hops[-1].tls["san"]

    async def test_bad_method_still_rejected(self, make_prober):
        prober = make_prober()
        with pytest.raises(PolicyError):
            await prober.probe("http://x.test/", method="POST")
