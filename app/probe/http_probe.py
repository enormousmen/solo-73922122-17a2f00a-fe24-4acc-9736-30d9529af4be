"""HTTP/HTTPS 出站探测引擎。

安全模型（每一跳都完整执行，跳转目标也不例外）：

  URL 静态校验 → DNS A 记录查询 → *全部* 解析地址过白名单
  → 仅向已批准 IP 建 TCP（运行时不再解析）→ HTTPS 按原域名校验证书
  → 发送一次请求 → 读取响应 → 若是跳转则对 Location 重复上述流程

因此：
* DNS 在检查后变化、连接重试、HTTP 跳转都不会让请求进入未获准网段；
* 被策略拒绝的目标在任何 socket 建立之前就被拦下，收不到探测请求；
* 每跳最多把已批准的地址各试一次，重试绝不重新解析 DNS。

时限与收尾模型：
* 每次探测有一个贯穿所有跳与所有阶段的总时限（``deadline``），DNS、
  TCP、TLS、读取与 *连接收尾* 都在该时限内有界执行；
* 总时限到达时抛出 :class:`DeadlineReached`（API 层转 408），而单阶段
  超时仍按跳内 error 处理；
* 每条连接在返回结论、释放调用方并发名额之前，都会经
  :func:`shutdown_writer` 有界收尾 —— 对端不回应 TLS 关闭也不会留下
  旧连接或悬挂任务；
* 已经取得的探测结论（状态码、跳转等）先落盘到 hop 报告，收尾只负责
  释放资源，不会把结论改报为超时。
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from .connection import (
    DeadlineReached,
    build_ssl_context,
    open_tcp,
    shutdown_writer,
    start_tls,
)
from .dns_client import DnsError, DnsResolver
from .policy import (
    AddressPolicy,
    PolicyError,
    is_ip_literal,
    parse_target,
)

DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 3
MAX_BYTES = 64 * 1024


@dataclass
class HopReport:
    hop: int
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_addresses: list[str] = field(default_factory=list)
    approved_addresses: list[str] = field(default_factory=list)
    connected_peer: str | None = None
    tls: dict | None = None
    request_sent: bool = False
    status_code: int | None = None
    reason: str | None = None
    location: str | None = None
    redirect_count: int = 0
    outcome: str = "pending"  # ok | redirected | blocked | error
    reject_reason: str | None = None
    error: str | None = None

    def mark_blocked(self, reason: str) -> None:
        self.outcome = "blocked"
        self.reject_reason = reason
        self.reason = reason

    def mark_error(self, message: str) -> None:
        self.outcome = "error"
        self.error = message
        self.reason = message


class Prober:
    def __init__(
        self,
        policy: AddressPolicy,
        resolver: DnsResolver,
        ca_bundle: str | None = None,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        tls_timeout: float = 8.0,
        close_timeout: float = 2.0,
        max_redirects: int = MAX_REDIRECTS,
        max_bytes: int = MAX_BYTES,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._ssl = build_ssl_context(ca_bundle)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._tls_timeout = tls_timeout
        self._close_timeout = close_timeout
        self._max_redirects = max_redirects
        self._max_bytes = max_bytes

    async def probe(
        self,
        url: str,
        method: str = "GET",
        deadline: float | None = None,
    ) -> list[HopReport]:
        """执行一次完整探测。

        deadline 为 ``loop.time()`` 基准的绝对总时限；为 None 时仅受各
        阶段超时约束（测试/直连场景）。总时限到达抛 DeadlineReached，
        已完成跳的信息保留在异常与返回路径之外的 hop 对象上。
        """
        method = method.upper()
        if method not in ("GET", "HEAD"):
            raise PolicyError("探测仅支持 GET/HEAD 方法")
        self._check_deadline(deadline)
        hops: list[HopReport] = []
        redirects = 0
        current = url
        while True:
            self._check_deadline(deadline)
            hop_idx = len(hops) + 1
            hop = HopReport(hop=hop_idx, url=current, scheme="", hostname="", port=0)
            hops.append(hop)
            try:
                next_url = await self._do_hop(hop, current, method, deadline)
            except DeadlineReached as exc:
                # 总时限到达：把当前跳标注为超时后向上抛，由 API 层转 408。
                # 已取得的状态码/跳转结论保持不变，绝不因收尾等待改报。
                if hop.status_code is None and hop.outcome == "pending":
                    hop.mark_error(
                        f"探测总时限到达，未取得响应（已完成 {hop.hop - 1} 跳）"
                    )
                exc.hops = hops
                raise
            if hop.outcome in ("blocked", "error"):
                return hops
            if next_url is None:
                hop.outcome = "ok"
                return hops
            # 发生跳转
            redirects += 1
            hop.redirect_count = redirects
            hop.outcome = "redirected"
            if redirects > self._max_redirects:
                limit_hop = HopReport(
                    hop=len(hops) + 1,
                    url=next_url,
                    scheme="",
                    hostname="",
                    port=0,
                )
                limit_hop.mark_blocked(
                    f"已跟随 {self._max_redirects} 次跳转，达到上限，"
                    f"拒绝继续访问: {next_url}"
                )
                hops.append(limit_hop)
                return hops
            current = next_url

    async def _do_hop(
        self,
        hop: HopReport,
        url: str,
        method: str,
        deadline: float | None,
    ) -> str | None:
        # 1) URL 静态校验（不产生任何网络流量）
        try:
            scheme, host, port, _user, raw = parse_target(url)
        except PolicyError as exc:
            hop.mark_blocked(str(exc))
            return None
        hop.scheme = scheme
        hop.hostname = host
        hop.port = port or DEFAULT_PORTS[scheme]

        # 2) 解析 + 白名单：IP 字面量直接校验；域名只问配置的解析器
        try:
            if is_ip_literal(host):
                resolved = [host]
            else:
                resolved = await self._resolve(host, deadline)
            hop.resolved_addresses = list(resolved)
            approved = self._policy.check_resolved(resolved)
            hop.approved_addresses = [str(ip) for ip in approved]
        except (PolicyError, DnsError) as exc:
            hop.mark_blocked(str(exc))
            return None

        # 3) 仅对已批准地址尝试连接，每个地址一次，绝不重新解析
        last_err: str | None = None
        for ip in approved:
            connected = await self._try_one_address(
                hop, ip, scheme, host, deadline
            )
            if connected is not None:
                reader, writer, tls_info = connected
                # 该地址连接成功：清除此前地址尝试留下的错误，避免残留
                hop.error = None
                try:
                    return await self._send_and_read(
                        hop, reader, writer, method, host, hop.port, url, deadline
                    )
                except PolicyError as exc:
                    # 响应阶段的策略性错误（如响应头超限、非法状态行）：
                    # 记录为本跳错误，不逃逸到 API 入口
                    hop.mark_error(str(exc))
                    return None
                finally:
                    # 关键：返回结论/归还名额前，本连接必须有界收尾完毕。
                    # 收尾计入总时限；对端不回应 TLS 关闭也只等到
                    # close_timeout 即强制 abort，绝不悬挂。
                    await shutdown_writer(
                        writer, self._close_timeout, deadline
                    )
            last_err = hop.error or hop.reject_reason
        # 所有已批准地址均连接失败
        hop.mark_error(f"全部已批准地址连接失败（未尝试任何未获准地址）: {last_err}")
        return None

    async def _resolve(self, host: str, deadline: float | None) -> list[str]:
        if deadline is None:
            return await self._resolver.resolve_a(host)
        try:
            return await asyncio.wait_for(
                self._resolver.resolve_a(host),
                timeout=self._remaining(deadline),
            )
        except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
            raise DeadlineReached("探测总时限已到（DNS 解析阶段）") from exc

    async def _try_one_address(
        self,
        hop,
        ip: ipaddress.IPv4Address,
        scheme: str,
        host: str,
        deadline: float | None,
    ):
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer, peer = await open_tcp(
                ip, hop.port, self._connect_timeout, deadline
            )
            hop.connected_peer = peer
            if scheme == "https":
                reader, writer, tls_info = await start_tls(
                    writer, reader, host, self._ssl, self._tls_timeout, deadline
                )
                hop.tls = asdict(tls_info)
            else:
                tls_info = None
            return reader, writer, tls_info
        except DeadlineReached:
            # 总时限到达：先有界释放可能已建立的传输，再向上抛
            if writer is not None:
                await shutdown_writer(writer, self._close_timeout, deadline)
            raise
        except PolicyError as exc:
            # 记录失败原因后继续试下一个 *已批准* 地址；
            # 若 TCP 已建立而 TLS 失败，同样先有界收尾，避免 writer 泄漏
            hop.connected_peer = None
            hop.tls = None
            hop.error = str(exc)
            if writer is not None:
                await shutdown_writer(writer, self._close_timeout, deadline)
            return None

    async def _send_and_read(
        self, hop: HopReport, reader, writer, method: str,
        host: str, port: int, url: str, deadline: float | None,
    ) -> str | None:
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        authority = host if (
            (parts.scheme == "http" and port == 80)
            or (parts.scheme == "https" and port == 443)
        ) else f"{host}:{port}"
        request_lines = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: egress-probe/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        try:
            writer.write(request_lines.encode("ascii", errors="replace"))
            await writer.drain()
            hop.request_sent = True
            response = await asyncio.wait_for(
                self._read_response(reader),
                timeout=self._phase_timeout(self._read_timeout, deadline),
            )
        except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
            if self._deadline_expired(deadline):
                raise DeadlineReached("探测总时限已到（读取响应阶段）") from exc
            hop.mark_error(f"读取响应超时（{self._read_timeout}s）")
            return None
        except OSError as exc:
            hop.mark_error(f"连接读写错误: {exc}")
            return None

        hop.status_code = response["status"]
        hop.reason = response["reason"]
        if response["status"] in REDIRECT_STATUSES:
            location = response["headers"].get("location")
            hop.location = location
            if not location:
                hop.mark_error(f"收到 {response['status']} 跳转但缺少 Location 头")
                return None
            try:
                next_url = normalize_redirect(url, location)
            except PolicyError as exc:
                # 跳转目标违反策略（非 HTTP(S)、userinfo 等）：在建立任何
                # 到目标的连接前拒绝，标记为 blocked 并保留已收到的 Location
                hop.mark_blocked(str(exc))
                return None
            return next_url
        return None

    async def _read_response(self, reader) -> dict:
        # 逐字节读到头部结束（慢服务器一次只发几个字节也能正确处理）；
        # body 优先按 Content-Length 读取 —— 这样对端“响应正常但不关闭
        # 连接（也不回应 TLS 关闭）”时，已取得的 200 结论不会被误判为
        # 读取超时；没有 Content-Length 时才在 Connection: close 下读到
        # 对端关闭，且整体只读取上限字节，超出即截断。
        header_blob = b""
        while b"\r\n\r\n" not in header_blob:
            chunk = await reader.read(1)
            if not chunk:
                break
            header_blob += chunk
            if len(header_blob) > self._max_bytes:
                raise PolicyError("响应头部超过大小上限")
        text = header_blob.decode("iso-8859-1")
        lines = text.split("\r\n")
        status_line = lines[0]
        if not status_line.startswith("HTTP/"):
            raise PolicyError(f"非法 HTTP 响应行: {status_line[:80]!r}")
        try:
            _proto, rest = status_line.split(" ", 1)
            status_text, reason = rest.split(" ", 1) if " " in rest else (rest, "")
            status = int(status_text)
        except (IndexError, ValueError) as exc:
            raise PolicyError(f"无法解析状态行: {status_line[:80]!r}") from exc
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        content_length = self._parse_content_length(headers)
        body_read = 0
        if content_length is not None:
            # 按声明长度读取，受 max_bytes 截断保护；不依赖对端关闭连接
            limit = min(content_length, self._max_bytes)
            while body_read < limit:
                chunk = await reader.read(limit - body_read)
                if not chunk:
                    break
                body_read += len(chunk)
        else:
            while body_read < self._max_bytes:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                body_read += len(chunk)
        return {"status": status, "reason": reason, "headers": headers}

    @staticmethod
    def _parse_content_length(headers: dict[str, str]) -> int | None:
        raw = headers.get("content-length")
        if raw is None:
            return None
        # 多个 Content-Length 或带空白的非法值一律视为不可信，回退到读到关闭
        token = raw.strip()
        if not token.isdigit():
            return None
        value = int(token)
        return value if value >= 0 else None

    # ------------------------------------------------------------ 时限工具
    def _remaining(self, deadline: float | None) -> float:
        if deadline is None:
            return None  # type: ignore[return-value]
        remaining = deadline - asyncio.get_running_loop().time()
        return max(remaining, 1e-9)

    def _phase_timeout(
        self, phase_timeout: float, deadline: float | None
    ) -> float:
        if deadline is None:
            return phase_timeout
        return min(phase_timeout, self._remaining(deadline))

    def _deadline_expired(self, deadline: float | None) -> bool:
        if deadline is None:
            return False
        return asyncio.get_running_loop().time() >= deadline

    def _check_deadline(self, deadline: float | None) -> None:
        if self._deadline_expired(deadline):
            raise DeadlineReached("探测总时限已到")


def normalize_redirect(base_url: str, location: str) -> str:
    """规范化跳转目标，并限制 scheme 为 http/https（相对 Location 也支持）。"""
    location = location.strip()
    if len(location) > 2048:
        raise PolicyError("跳转 Location 过长")
    if location.startswith("//"):
        # 协议相对 URL：继承当前 scheme
        location = urlsplit(base_url).scheme + ":" + location
    next_url = urljoin(base_url, location)
    scheme = urlsplit(next_url).scheme.lower()
    if scheme not in ("http", "https"):
        raise PolicyError(
            f"跳转到非 HTTP(S) 协议 {scheme!r}，拒绝: {next_url}"
        )
    if urlsplit(next_url).username is not None:
        raise PolicyError("跳转目标 URL 禁止携带 userinfo")
    return next_url
