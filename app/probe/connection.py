"""面向已批准 IPv4 地址的低层连接。

关键约束：
* ``open_connection`` 的 remote 永远是策略已批准的 IP 字面量，运行时
  不会再次解析 DNS —— 因此“检查后 DNS 换址”无法把连接带进未获准网段；
* HTTPS 使用 ``server_hostname=原域名`` 建立 SNI 并按原域名验证证书，
  ``check_hostname=True`` 且使用受信 CA 集合，调用方无法关闭校验；
* 连接收尾（含 TLS 关闭）是有界的：对端不回应 TLS close_notify 时，
  等待超过 close_timeout 即强制 ``abort()`` 底层传输，保证旧连接不会
  长期占用、通信任务一定退出。
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass

from .policy import PolicyError

# 收尾阶段的最小强制上限：即使总时限已耗尽，也只再等这么久就 abort，
# 避免对端完全不回应时任务永久挂住、名额永不释放。
MIN_ABORT_GRACE = 0.5


@dataclass
class TlsInfo:
    version: str
    cipher: str
    subject: str
    san: list[str]
    peer_cert_subject: str


async def open_tcp(
    approved_ip: ipaddress.IPv4Address,
    port: int,
    connect_timeout: float,
    deadline: float | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    """打开到指定已批准 IP 的裸 TCP 连接，返回 (reader, writer, peer)。

    deadline 为本次探测的总时限（loop.time() 基准）；阶段超时同时受
    connect_timeout 与“剩余总时限”约束，任一个先到即失败。
    """
    peer = f"{approved_ip}:{port}"
    timeout = _bounded_timeout(connect_timeout, deadline)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(approved_ip), port),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        if _deadline_expired(deadline):
            raise DeadlineReached(f"探测总时限已到（TCP 连接阶段: {peer}）") from exc
        raise PolicyError(f"TCP 连接超时: {peer}") from exc
    except OSError as exc:
        raise PolicyError(f"TCP 连接失败: {peer} ({exc.strerror or exc})") from exc
    return reader, writer, peer


def build_ssl_context(ca_bundle: str | None) -> ssl.SSLContext:
    """构造强制校验的 TLS 上下文。

    ca_bundle 为 None 时使用系统信任库；否则使用指定的 CA 合并文件
    （演示环境把测试 CA 与系统 CA 合并，既信任测试证书又保留公网信任）。
    """
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=ca_bundle,
    )
    ctx.check_hostname = True  # 显式固定：按原域名校验
    ctx.verify_mode = ssl.CERT_REQUIRED  # 显式固定：必须校验证书
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


async def start_tls(
    writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    hostname: str,
    context: ssl.SSLContext,
    handshake_timeout: float,
    deadline: float | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, TlsInfo]:
    timeout = _bounded_timeout(handshake_timeout, deadline)
    try:
        # Python 3.11 兼容路径：在已有传输上启动 TLS
        await asyncio.wait_for(
            writer.start_tls(context, server_hostname=hostname),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        if _deadline_expired(deadline):
            raise DeadlineReached(
                f"探测总时限已到（TLS 握手阶段，域名 {hostname}）"
            ) from exc
        raise PolicyError(f"TLS 握手超时（域名 {hostname}）") from exc
    except ssl.SSLCertVerificationError as exc:
        # 证书/主机名校验失败：明确告知，且不提供任何“跳过校验”的选项
        raise PolicyError(
            f"TLS 证书校验失败（按原域名 {hostname!r} 验证，未关闭校验）: "
            f"{exc.verify_message or exc}"
        ) from exc
    except ssl.SSLError as exc:
        raise PolicyError(f"TLS 握手失败: {exc}") from exc
    except OSError as exc:
        raise PolicyError(f"TLS 握手 IO 错误: {exc}") from exc

    # start_tls 会把底层传输替换为 TLS 传输，reader/writer 原地生效
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj is None:
        raise PolicyError("TLS 启动后未取得 SSL 对象")
    cert = ssl_obj.getpeercert()
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    subject = _cert_name(cert.get("subject"))
    info = TlsInfo(
        version=ssl_obj.version() or "unknown",
        cipher=(ssl_obj.cipher() or ("unknown",))[0],
        subject=subject,
        san=sans,
        peer_cert_subject=subject,
    )
    return reader, writer, info


async def shutdown_writer(
    writer: asyncio.StreamWriter,
    close_timeout: float,
    deadline: float | None = None,
) -> None:
    """有界地关闭连接并等待底层传输真正退出。

    * 先尝试优雅关闭（TLS 下发送 close_notify 并等待对端回应）；
    * 优雅等待同时受 ``close_timeout`` 与本次探测总时限约束；
    * 超时（或总时限已到、对端不回应 TLS 关闭）则直接 ``abort()``
      底层传输，再以一个很小的强制上限等待退出 —— 因此无论对端行为
      如何，本协程一定在有界时间内返回，调用方的并发名额必然能归还。

    已经取得的探测结论在调用本函数之前就已确定，收尾只负责释放资源，
    不会也不能把结论改报为超时。
    """
    if writer.is_closing():
        # 传输已在关闭流程中：仍等待其退出，但同样要有界
        await _wait_aborted(writer, deadline)
        return

    graceful = _bounded_timeout(close_timeout, deadline)
    writer.close()
    try:
        await bounded_wait(writer.wait_closed(), timeout=graceful)
        return
    except asyncio.TimeoutError:
        # 对端不回应 TLS close_notify（或 TCP 不关闭）：强制中止
        pass
    except asyncio.CancelledError:
        # 总时限已耗尽、timeout 极小时可能以取消形式结束：转入强制 abort
        pass
    except (OSError, ssl.SSLError):
        # 关闭过程中对端已重置等：传输随后会退出，下面统一兜底
        pass
    await _abort(writer)


async def _wait_aborted(writer: asyncio.StreamWriter, deadline: float | None) -> None:
    # 总时限可能已耗尽，这里只用固定的很小上限，保证快速退出
    try:
        await bounded_wait(writer.wait_closed(), timeout=MIN_ABORT_GRACE)
    except asyncio.CancelledError:
        pass
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        await _abort(writer)


async def _abort(writer: asyncio.StreamWriter) -> None:
    transport = writer.transport
    abort = getattr(transport, "abort", None)
    if callable(abort):
        # abort 立即关闭底层 socket，丢弃缓冲，不等对端
        abort()
    else:  # pragma: no cover - 全部标准传输均实现 abort
        transport.close()
    try:
        await bounded_wait(writer.wait_closed(), timeout=MIN_ABORT_GRACE)
    except asyncio.CancelledError:
        # 传输已 abort，关闭等待任务可能本身已被取消；资源回收由事件循环
        # 在 socket 关闭后完成，这里不能让取消异常逃逸而吞掉原始结论
        pass
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        # 极端情况下仍未退出也不再等待：资源已由 abort 触发回收，
        # 事件循环会在 socket 关闭后完成收尾，不阻塞调用方返回
        pass


def _bounded_timeout(phase_timeout: float, deadline: float | None) -> float:
    """取阶段超时与总时限剩余值中的较小者，且始终为正数。"""
    if deadline is None:
        return phase_timeout
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        # 已过期：给一个极小正值，让 wait_for 立即走超时分支
        return 1e-9
    return min(phase_timeout, remaining)


async def bounded_wait(aw, timeout: float) -> None:
    """``wait_for`` 的健壮封装：timeout 极小时也统一抛 TimeoutError。

    Python 3.11 的 ``wait_for`` 在协程尚未启动就被超时时取消，可能直接
    抛 ``CancelledError`` 而非 ``TimeoutError``；这里归一化，避免取消
    异常逃逸到探测流程。
    """
    try:
        await asyncio.wait_for(aw, timeout=timeout)
    except asyncio.CancelledError:
        if timeout <= 1e-6:
            raise asyncio.TimeoutError()
        raise


def _deadline_expired(deadline: float | None) -> bool:
    if deadline is None:
        return False
    return asyncio.get_running_loop().time() >= deadline


class DeadlineReached(Exception):
    """本次探测的总时限已到（区别于单阶段超时）。

    由 API 层捕获并转换为 HTTP 408；``hops`` 携带超时前已完成的
    逐跳信息（可能为空列表）。
    """

    def __init__(self, message: str, hops: list | None = None) -> None:
        super().__init__(message)
        self.hops = hops or []


def _cert_name(rdn_sequence) -> str:
    if not rdn_sequence:
        return ""
    parts: list[str] = []
    for rdn in rdn_sequence:
        parts.extend(f"{k}={v}" for k, v in rdn)
    return ", ".join(parts)
