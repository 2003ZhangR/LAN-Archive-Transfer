"""局域网 ZIP / RAR 作业上传：传输实现位于本文件，仅依赖 Python 3.12+ 标准库。

上传接口：先 login_student 登录，再 upload_file(..., session_token=登录令牌)。
学生账户就是学号，教师端按 保存目录 / 学号 / 文件名 归档。
同一学号目录下的同名文件默认覆盖；新文件接收并校验成功后才原子替换旧文件。
并发提交同名文件时，最后成功完成保存的文件生效。
批量并发：upload_files([UploadJob(文件路径, 学号, 教师IP)], max_workers=4)
重试会从文件开头重新发送；默认失败后最多重试两次，间隔 1、2 秒。
同一接收进程保留最近 4096 条成功确认，重试用同一提交编号避免重复保存。
接收进程重启或确认记录被淘汰后，重试会按同名覆盖规则再次保存。
本工具验证扩展名、ZIP/RAR4/RAR5 文件头及 SHA256，不压缩、不解压。
monitoring.py 提供学生知情启用的统计与告警；send 自动附带该学号已有的隐藏日志。
编程接口通过 status_file 指定日志，所有 ZIP/RAR 上传均须传入登录令牌。

命令行：
  python upload.py receive --save-dir "D:/学生作业"
  python upload.py send --ip 192.168.1.20 --student-account 20260001 --file "D:/作业.zip"
  python upload.py send --ip 192.168.1.20 --student-account 20260001 --file "D:/1.zip" --file "D:/2.rar" --workers 4 --retries 2

upload_file / upload_files 为同步接口；GUI 应在后台线程中调用。
进度回调在工作线程执行，done / total 使用 Python 整数，支持大于 4 GB 的文件。
"""

import argparse
import base64
import binascii
import errno
import hashlib
import hmac
import http.client
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import stat
import sys
import threading
import time
import unicodedata
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, Callable, Iterable

from accounts import AUTH_FEATURE, DEFAULT_DB, AccountDatabase, AccountError, Authenticator, validate_password


class TransferError(Exception):
    """可直接显示给用户的中文错误。"""

    def __init__(self, message: str, status: int = 400, retryable: bool = False):
        super().__init__(message)
        self.message = message
        self.status = status
        self.retryable = retryable


class UploadCancelled(TransferError):
    def __init__(self):
        super().__init__("已取消上传。未完成的数据不会保存为正式作业。")


ZIP_HEADERS = (b"PK\x03\x04", b"PK\x05\x06")


RAR4_HEADER = b"Rar!\x1a\x07\x00"


RAR5_HEADER = b"Rar!\x1a\x07\x01\x00"


_INVALID = set('<>:"/\\|?*')


_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)


def validate_component(value: str, label: str, limit: int):
    if not isinstance(value, str) or not value:
        raise TransferError(f"{label}不能为空。")
    if any(c in _INVALID or unicodedata.category(c).startswith("C") for c in value):
        raise TransferError(f"{label}含有非法字符或路径，不能包含 /、\\、冒号或控制字符。")
    if len(value.encode("utf-16-le")) // 2 > limit:
        raise TransferError(f"{label}不能超过 {limit} 个字符。")
    if value != value.strip() or value.endswith((".", " ")) or value in (".", ".."):
        raise TransferError(f"{label}首尾不能有空格，结尾不能是点号，也不能是相对路径。")
    if _RESERVED.match(value):
        raise TransferError(f"{label}不能使用 Windows 保留名称，例如 CON、NUL。")


def validate_student_account(student_account: str) -> str:
    """学生账户就是学号，以字符串保留前导零，并作为保存目录名。"""
    if not isinstance(student_account, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", student_account, flags=re.ASCII):
        raise TransferError("学生账户（学号）须为 1–32 位数字、英文字母、下划线或短横线。")
    validate_component(student_account, "学生账户（学号）", 32)
    return student_account


def validate_filename(filename: str) -> str:
    validate_component(filename, "文件名", 160)
    suffix = Path(filename).suffix.lower()
    if suffix not in (".zip", ".rar"):
        raise TransferError("只允许提交已经压缩好的 .zip 或 .rar 文件，不能提交普通文件和文件夹。")
    if not Path(filename).stem or Path(filename).stem.endswith((".", " ")):
        raise TransferError("压缩文件名称无效，请重命名后再提交。")
    return suffix


def validate_header(header: bytes, filename: str, size: int) -> str:
    suffix = validate_filename(filename)
    if suffix == ".zip" and header.startswith(ZIP_HEADERS) and size >= 22:
        return "ZIP"
    if suffix == ".rar" and header.startswith(RAR5_HEADER) and size > len(RAR5_HEADER):
        return "RAR5"
    if suffix == ".rar" and header.startswith(RAR4_HEADER) and size > len(RAR4_HEADER):
        return "RAR4"
    raise TransferError("文件格式错误：扩展名与真实 ZIP / RAR4 / RAR5 文件头不匹配，请勿只修改扩展名。")


def validate_open_file(stream: BinaryIO, filename: str) -> tuple[int, str]:
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode):
        raise TransferError("请选择普通压缩文件，不能提交文件夹或特殊文件。")
    original = stream.tell()
    stream.seek(0)
    header = stream.read(8)
    stream.seek(original)
    return info.st_size, validate_header(header, filename, info.st_size)


PORT = 9000


CHUNK_SIZE = 1024 * 1024


METADATA_HEADER = "X-Submission-Metadata"


PROTOCOL = "lan-archive/3"


STATUS_FEATURE = "programming-status-v1"
HISTORY_FEATURE = "programming-status-history-v1"
ACTIVITY_LOG_SCHEMA = "lan-programming-status-receipts/1"


STATUS_HASH_HEADER = "X-Programming-Status-SHA256"


IDLE_TIMEOUT = 120.0


MAX_CONNECTIONS = 64


@dataclass(frozen=True)
class Submission:
    student_account: str
    filename: str
    size: int
    sha256: str
    upload_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def validate(self):
        validate_student_account(self.student_account)
        validate_filename(self.filename)
        if type(self.size) is not int or not 0 < self.size < 2**63:
            raise TransferError("文件大小无效。")
        if not isinstance(self.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise TransferError("SHA256 校验参数无效。")
        if not isinstance(self.upload_id, str) or not re.fullmatch(r"[0-9a-f]{32}", self.upload_id):
            raise TransferError("提交编号无效。")

    def encode(self) -> str:
        self.validate()
        raw = json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    @classmethod
    def decode(cls, text: str) -> "Submission":
        if not text or len(text) > 4096:
            raise TransferError("提交信息缺失或过长。")
        try:
            fields = json.loads(base64.b64decode(text, validate=True).decode("utf-8"))
            if not isinstance(fields, dict) or set(fields) != set(cls.__dataclass_fields__):
                raise ValueError("invalid fields")
            value = cls(**fields)
            value.validate()
            return value
        except TransferError:
            raise
        except (ValueError, TypeError, UnicodeError, binascii.Error) as exc:
            raise TransferError("提交信息格式错误。") from exc


@dataclass(frozen=True)
class Progress:
    """回调在传输线程执行；GUI 集成时应经信号送回主线程。"""

    phase: str
    done: int
    total: int
    speed: float
    status: str
    task_id: str = ""
    student_account: str = ""
    filename: str = ""
    saved_path: str = ""
    attempt: int = 1

    @property
    def percentage(self) -> float:
        return min(100.0, self.done * 100 / self.total) if self.total else 0.0


def format_size(size: int | float) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024 or unit == "PB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value:.0f} B"
        value /= 1024
    return ""


def validate_ip(text: str) -> str:
    if not isinstance(text, str):
        raise TransferError("教师电脑 IP 须以字符串传入。")
    try:
        address = ipaddress.IPv4Address(text.strip())
    except ipaddress.AddressValueError as exc:
        raise TransferError("请输入教师电脑的 IPv4 地址，例如 192.168.1.20。") from exc
    if address.is_unspecified or address.is_multicast or address.is_reserved or int(address) == 0xFFFFFFFF:
        raise TransferError("该 IP 不是可连接的教师电脑地址。")
    return str(address)


def local_ipv4_addresses() -> list[str]:
    try:
        values = {item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
        values = {value for value in values if not ipaddress.IPv4Address(value).is_loopback
                  and not ipaddress.IPv4Address(value).is_link_local and value != "0.0.0.0"}
        return sorted(values, key=lambda value: (not ipaddress.IPv4Address(value).is_private, int(ipaddress.IPv4Address(value))))
    except OSError:
        return []


def _normalize_resolved_path(path: Path) -> Path:
    # Windows may retain its extended-path prefix when resolve() races with
    # creation of an intermediate directory. Normalize drive and UNC forms
    # before containment comparisons; this does not relax component validation.
    if os.name == "nt":
        text = str(path)
        if text.startswith("\\\\?\\UNC\\"):
            return Path("\\\\" + text[8:])
        if text.startswith("\\\\?\\") and len(text) > 6 and text[5:7] == ":\\":
            return Path(text[4:])
    return path


def disk_error(exc: OSError) -> TransferError:
    if exc.errno == errno.ENOSPC or getattr(exc, "winerror", None) == 112:
        return TransferError("教师电脑磁盘空间不足，作业未保存，请联系教师。", 507)
    return TransferError("无法写入作业，请检查保存目录权限、路径或磁盘状态。", 500)


class SafeStorage:
    def __init__(self, root: Path):
        try:
            root.mkdir(parents=True, exist_ok=True)
            self.root = _normalize_resolved_path(root.resolve(strict=True))
            if not self.root.is_dir():
                raise TransferError("保存位置必须是文件夹。")
            probe = self.root / f".write-test-{uuid.uuid4().hex}.uploading"
            with probe.open("xb"):
                pass
            probe.unlink()
        except OSError as exc:
            raise TransferError("无法创建或写入保存目录，请检查权限。") from exc
        self.commit_lock = threading.Lock()

    def checked_path(self, path: Path) -> Path:
        resolved = _normalize_resolved_path(path.resolve())
        if not path.is_relative_to(self.root) or not resolved.is_relative_to(self.root):
            raise TransferError("保存路径越出作业目录，已拒绝提交。")
        current = path
        while current != self.root:
            if current.exists() or current.is_symlink():
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise TransferError("保存路径含有符号链接或目录联接，已拒绝提交。")
            current = current.parent
        if os.name == "nt" and len(str(path)) > 240:
            raise TransferError("保存路径过长，请使用更短的保存目录或文件名。")
        return path

    def begin(self, submission: Submission) -> "IncomingFile":
        submission.validate()
        directory = self.checked_path(self.root / submission.student_account)
        self.checked_path(directory / submission.filename)
        directory.mkdir(exist_ok=True)
        self.checked_path(directory)
        if not directory.is_dir():
            raise TransferError("学生作业目录被同名文件占用，请联系教师。")
        if shutil.disk_usage(self.root).free < submission.size:
            raise TransferError("教师电脑磁盘空间不足。", 507)
        temporary = self.checked_path(directory / f".{uuid.uuid4().hex}.uploading")
        return IncomingFile(self, submission, temporary)

    def commit(self, temporary: Path, filename: str) -> Path:
        with self.commit_lock:
            target = self.checked_path(temporary.parent / filename)
            self.checked_path(temporary)
            # finish() has verified and closed the temporary file. Keeping both
            # paths in the same directory allows atomic replacement without
            # deleting the previous submission before the new one is ready.
            os.replace(temporary, target)
            return target


class IncomingFile:
    def __init__(self, storage: SafeStorage, submission: Submission, temporary: Path):
        self.storage, self.submission, self.temporary = storage, submission, temporary
        self.stream = temporary.open("xb")
        self.received = 0
        self.header = b""
        self.digest = hashlib.sha256()
        self.completed = False

    def write(self, chunk: bytes):
        if self.received + len(chunk) > self.submission.size:
            raise TransferError("接收数据超过声明大小，已拒绝提交。")
        if len(self.header) < 8:
            self.header += chunk[:8 - len(self.header)]
            if len(self.header) == 8:
                validate_header(self.header, self.submission.filename, self.submission.size)
        self.stream.write(chunk)
        self.digest.update(chunk)
        self.received += len(chunk)

    def finish(self) -> Path:
        if self.received != self.submission.size:
            raise TransferError("文件传输不完整，请重新提交。")
        validate_header(self.header, self.submission.filename, self.received)
        if not hmac.compare_digest(self.digest.hexdigest(), self.submission.sha256):
            raise TransferError("SHA256 校验失败，文件可能被修改或传输损坏，请重新提交。", 422)
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        with self.temporary.open("rb") as stream:
            validate_header(stream.read(8), self.submission.filename, self.temporary.stat().st_size)
        target = self.storage.commit(self.temporary, self.submission.filename)
        self.completed = True
        return target

    def abort(self):
        if not self.stream.closed:
            self.stream.close()
        if not self.completed:
            self.temporary.unlink(missing_ok=True)


def _response_json(response: http.client.HTTPResponse) -> dict:
    try:
        raw = response.read(16385)
        if len(raw) > 16384:
            raise ValueError("response too large")
        fields = json.loads(raw)
        if not isinstance(fields, dict):
            raise ValueError("invalid response")
    except (ValueError, UnicodeError) as exc:
        raise TransferError("教师端响应无效，请核对 IP 地址及接收脚本版本。") from exc
    if response.status != 200 or fields.get("ok") is not True:
        message = fields.get("message")
        message = message if isinstance(message, str) and len(message) < 500 else "教师端拒绝本次提交，请联系教师。"
        retryable = response.status in (408, 422, 429, 502, 503, 504) or fields.get("retryable") is True
        raise TransferError(message, response.status, retryable)
    return fields


def _request_json(ip: str, port: int, path: str, headers: dict | None = None, *,
                  body: dict | None = None) -> dict:
    connection = http.client.HTTPConnection(ip, port, timeout=8)
    try:
        request_headers = {"Connection": "close", **(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json; charset=utf-8"
        connection.request("POST" if body is not None else "GET", path, body=data, headers=request_headers)
        return _response_json(connection.getresponse())
    finally:
        connection.close()


def check_receiver(receiver_ip: str, *, port: int = PORT, require_status: bool = False) -> dict:
    """供图形界面连接检查使用，不上传文件，也不启动监控。"""
    ip = validate_ip(receiver_ip)
    if type(port) is not int or not 1 <= port <= 65535:
        raise TransferError("接收端口无效。")
    try:
        health = _request_json(ip, port, "/health")
    except (OSError, http.client.HTTPException) as exc:
        raise TransferError("无法连接教师电脑，请检查 IP、局域网和教师端接收服务（TCP 9000）。") from exc
    if health.get("protocol") != PROTOCOL:
        raise TransferError("该地址不是兼容的教师接收端，请核对 IP 和程序版本。")
    if require_status and STATUS_FEATURE not in health.get("features", []):
        raise TransferError("教师端尚不支持监控日志，请将 upload.py 和 monitoring.py 一起更新。")
    if require_status and HISTORY_FEATURE not in health.get("features", []):
        raise TransferError("教师端尚不支持监控历史与登录信息，请将 upload.py 和 monitoring.py 一起更新。")
    return health


def auth_headers(token: str) -> dict:
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise TransferError("请先使用账号密码登录，取得有效登录会话。", 401)
    return {"Authorization": f"Bearer {token}"}


def login_student(receiver_ip: str, student_account: str, password: str, *,
                  port: int = PORT, require_status: bool = False) -> dict:
    ip = validate_ip(receiver_ip)
    validate_student_account(student_account)
    try:
        validate_password(password)
    except AccountError as exc:
        raise TransferError(str(exc), exc.status) from exc
    health = check_receiver(ip, port=port, require_status=require_status)
    if AUTH_FEATURE not in health.get("features", []) or health.get("authentication_required") is not True:
        raise TransferError("教师端尚未启用账号密码验证，请先更新教师端程序。")
    try:
        result = _request_json(ip, port, "/auth/login", body=dict(student_account=student_account, password=password))
    except (OSError, http.client.HTTPException) as exc:
        raise TransferError("登录时无法连接教师电脑，请检查网络后重试。", 503) from exc
    auth_headers(result.get("token"))
    if (result.get("student_account") != student_account or not isinstance(result.get("expires_at"), str)):
        raise TransferError("教师端登录响应无效，请联系教师。")
    try:
        if datetime.fromisoformat(result["expires_at"]).tzinfo is None:
            raise ValueError("missing timezone")
    except ValueError as exc:
        raise TransferError("教师端登录有效期无效，请联系教师。") from exc
    return result


def logout_student(receiver_ip: str, token: str, *, port: int = PORT):
    ip = validate_ip(receiver_ip)
    try:
        _request_json(ip, port, "/auth/logout", auth_headers(token), body={})
    except (OSError, http.client.HTTPException) as exc:
        raise TransferError("无法通知教师端退出，登录令牌将在有效期结束后失效。", 503) from exc


def change_student_password(receiver_ip: str, token: str, old_password: str, new_password: str,
                            *, port: int = PORT) -> dict:
    ip = validate_ip(receiver_ip)
    try:
        validate_password(new_password)
        return _request_json(ip, port, "/auth/change-password", auth_headers(token),
                             body=dict(old_password=old_password, new_password=new_password))
    except AccountError as exc:
        raise TransferError(str(exc), exc.status) from exc
    except (OSError, http.client.HTTPException) as exc:
        raise TransferError("修改密码时连接失败，请检查网络。", 503) from exc


def _check_receipt(result: dict, metadata: Submission) -> dict:
    if (result.get("size") != metadata.size or not isinstance(result.get("sha256"), str)
            or not hmac.compare_digest(result["sha256"], metadata.sha256)):
        raise TransferError("接收确认中的大小或 SHA256 不一致，请联系教师核查。")
    if result.get("student_account") != metadata.student_account or result.get("upload_id") != metadata.upload_id:
        raise TransferError("接收确认中的学号或提交编号不一致，请联系教师核查。")
    validate_component(result.get("filename"), "返回文件名", 240)
    if Path(result["filename"]).suffix.lower() != Path(metadata.filename).suffix.lower():
        raise TransferError("接收确认中的文件格式不一致。")
    return result


def _send_stream(ip, port, stream, metadata, emit, check_cancel, token):
    connection = http.client.HTTPConnection(ip, port, timeout=8)
    try:
        stream.seek(0)
        connection.connect()
        connection.sock.settimeout(30.0)
        connection.putrequest("POST", "/upload")
        connection.putheader("Authorization", auth_headers(token)["Authorization"])
        connection.putheader(METADATA_HEADER, metadata.encode())
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(metadata.size))
        connection.putheader("Connection", "close")
        connection.endheaders()
        emit("uploading", 0, 0, "正在上传")
        sent, speed_bytes, speed = 0, 0, 0.0
        speed_time = last_emit = time.monotonic()
        digest = hashlib.sha256()
        while sent < metadata.size:
            check_cancel()
            chunk = stream.read(min(CHUNK_SIZE, metadata.size - sent))
            if not chunk:
                raise TransferError("文件在上传过程中被截断，请重新选择文件。")
            digest.update(chunk)
            connection.send(chunk)
            sent += len(chunk)
            now = time.monotonic()
            if now - speed_time >= 0.2 or sent == metadata.size:
                speed = (sent - speed_bytes) / max(now - speed_time, 0.001)
                speed_time, speed_bytes = now, sent
            if now - last_emit >= 0.1 or sent == metadata.size:
                emit("uploading", sent, speed, "正在上传")
                last_emit = now
        if not hmac.compare_digest(digest.hexdigest(), metadata.sha256):
            raise TransferError("文件在上传过程中被修改，SHA256 校验失败，请重新提交。")
        emit("verifying", sent, 0, "文件已发送，等待教师端校验并保存")
        connection.sock.settimeout(120.0)
        return _check_receipt(_response_json(connection.getresponse()), metadata)
    finally:
        connection.close()


def _send_status(ip, port, metadata, data, status_sha256, token):
    connection = http.client.HTTPConnection(ip, port, timeout=30)
    try:
        connection.request("POST", "/activity", body=data, headers={
            METADATA_HEADER: metadata.encode(), STATUS_HASH_HEADER: status_sha256,
            "Content-Type": "application/json; charset=utf-8", "Content-Length": str(len(data)),
            "Connection": "close",
            **auth_headers(token),
        })
        result = _response_json(connection.getresponse())
        if (result.get("upload_id") != metadata.upload_id
                or result.get("student_account") != metadata.student_account
                or result.get("status_sha256") != status_sha256
                or result.get("status_filename") not in (
                    f".programming-status-{metadata.student_account}.json",
                    f".programming-status-{metadata.upload_id}.json")):
            raise TransferError("监控日志接收确认的学号、提交编号或 SHA256 不匹配。")
        return result
    finally:
        connection.close()


def upload_file(file_path: str | Path, student_account: str, receiver_ip: str, *,
                port: int = PORT, retries: int = 2, retry_delay: float = 1.0,
                progress: Callable[[Progress], None] | None = None,
                cancel: threading.Event | None = None,
                status_file: str | Path | None = None, session_token: str | None = None) -> dict:
    """上传一个 ZIP / RAR 文件，包含自动重试、流式发送、完整性确认。

    retries 是首次失败后的重试次数，0 表示不重试，最大 10。
    网络错误、接收繁忙、传输校验失败可重试；格式、路径和本地文件修改不重试。
    重试整文件重传，同一调用保留提交编号、文件描述符及已计算的 SHA256。
    status_file 可附带监控日志快照；作业确认后发送日志，全部成功才发出 done。
    日志失败时重试同一提交，不重复上传已经确认保存的作业。
    session_token 须由 login_student 取得。
    """
    ip = validate_ip(receiver_ip)
    validate_student_account(student_account)
    headers = auth_headers(session_token)
    if type(retries) is not int or not 0 <= retries <= 10:
        raise TransferError("重试次数须为 0–10 的整数。")
    if type(retry_delay) not in (int, float) or not 0 <= retry_delay <= 30:
        raise TransferError("重试间隔须为 0–30 秒。")
    if type(port) is not int or not 1 <= port <= 65535:
        raise TransferError("接收端口无效。")
    if not isinstance(file_path, (str, Path)):
        raise TransferError("文件路径须以字符串或 Path 传入。")
    path = Path(file_path)
    cancel = cancel or threading.Event()
    upload_id = uuid.uuid4().hex
    size, attempt, done = 0, 1, 0
    metadata = None
    status_data, status_sha256 = None, None
    history_required = False
    archive_saved = False

    def check_cancel():
        if cancel.is_set():
            raise UploadCancelled()

    def emit(phase, count, speed, status):
        nonlocal done
        done = count
        if progress:
            progress(Progress(phase, count, size, speed, status, task_id=upload_id,
                              student_account=student_account, filename=path.name, attempt=attempt))

    try:
        check_cancel()
        if status_file is not None:
            if not isinstance(status_file, (str, Path)):
                raise TransferError("监控日志路径无效。")
            try:
                from monitoring import read_status_file, MonitorError
            except ImportError as exc:
                raise TransferError("缺少监控日志模块，请将 monitoring.py 放到 upload.py 同一目录。") from exc
            try:
                status_data = read_status_file(status_file, student_account)
                history_required = json.loads(status_data).get("schema") != "lan-programming-status/1"
                status_sha256 = hashlib.sha256(status_data).hexdigest()
            except (MonitorError, OSError) as exc:
                raise TransferError(f"无法读取监控日志：{exc}") from exc
        if not path.is_file():
            raise TransferError("请选择已压缩的普通 .zip / .rar 文件，不能提交文件夹。")
        with path.open("rb") as stream:
            size, kind = validate_open_file(stream, path.name)
            before = os.fstat(stream.fileno())
            for attempt in range(1, retries + 2):
                error = None
                try:
                    check_cancel()
                    emit("connecting", 0, 0, "正在连接教师电脑")
                    health = _request_json(ip, port, "/health")
                    if health.get("protocol") != PROTOCOL:
                        raise TransferError("该地址不是兼容的教师接收端，请核对 IP 和程序版本。")
                    if AUTH_FEATURE not in health.get("features", []) or health.get("authentication_required") is not True:
                        raise TransferError("教师端尚未启用账号密码验证，请先更新教师端程序。")
                    if status_data is not None and STATUS_FEATURE not in health.get("features", []):
                        raise TransferError("教师接收端尚不支持监控日志，请先更新教师端 upload.py 和 monitoring.py。")
                    if history_required and HISTORY_FEATURE not in health.get("features", []):
                        raise TransferError("教师端尚不支持监控历史与登录信息，请一起更新 upload.py 和 monitoring.py。")
                    if metadata is None:
                        emit("hashing", 0, 0, f"正在计算 {kind} 文件的 SHA256（尚未上传）")
                        stream.seek(0)
                        digest, hashed = hashlib.sha256(), 0
                        started = last_emit = time.monotonic()
                        while hashed < size:
                            check_cancel()
                            chunk = stream.read(min(CHUNK_SIZE, size - hashed))
                            if not chunk:
                                raise TransferError("文件在校验过程中被截断。")
                            digest.update(chunk)
                            hashed += len(chunk)
                            now = time.monotonic()
                            if now - last_emit >= 0.1 or hashed == size:
                                emit("hashing", hashed, hashed / max(now - started, 0.001), "正在计算 SHA256（尚未上传）")
                                last_emit = now
                        if stream.read(1):
                            raise TransferError("文件在校验过程中被修改，请重新选择文件。")
                        metadata = Submission(student_account, path.name, size, digest.hexdigest(), upload_id)
                    current = os.fstat(stream.fileno())
                    if (before.st_size, before.st_mtime_ns) != (current.st_size, current.st_mtime_ns):
                        raise TransferError("文件在传输过程中被修改，请关闭编辑软件后重新提交。")
                    emit("connecting", 0, 0, "正在确认教师端提交状态")
                    state = _request_json(ip, port, "/status", {METADATA_HEADER: metadata.encode(), **headers})
                    if state.get("state") == "completed":
                        result = _check_receipt(state, metadata)
                    elif state.get("state") == "receiving":
                        raise TransferError("上一次上传仍在接收或清理，请稍后重试。", 409, True)
                    elif state.get("state") == "ready":
                        result = _send_stream(ip, port, stream, metadata, emit, check_cancel, session_token)
                    else:
                        raise TransferError("教师端提交状态响应异常。")
                    archive_saved = True
                    if status_data is not None:
                        check_cancel()
                        emit("status", size, 0, "作业文件已保存，正在提交软件使用与告警日志")
                        receipt = _send_status(ip, port, metadata, status_data, status_sha256, session_token)
                        result.update(status_log_saved=True, status_filename=receipt["status_filename"],
                                      status_sha256=status_sha256)
                    emit("done", size, 0, "作业提交成功（监控日志已提交）" if status_data is not None else "作业提交成功")
                    return result
                except UploadCancelled:
                    raise
                except TransferError as exc:
                    error = exc
                except (ConnectionError, TimeoutError, socket.gaierror, http.client.HTTPException) as exc:
                    error = TransferError("无法连接教师电脑或网络传输中断。请检查 IP、局域网、接收服务及防火墙 TCP 9000。", 503, True)
                    error.__cause__ = exc
                except OSError as exc:
                    network = (10000 <= getattr(exc, "winerror", 0) < 11000 or exc.errno in
                               (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.ETIMEDOUT, errno.ECONNRESET, errno.EPIPE))
                    error = TransferError("网络连接失败，请检查网络与防火墙。" if network else "无法读取文件，请检查权限和磁盘状态。", 503 if network else 400, network)
                    error.__cause__ = exc
                if not error.retryable or attempt > retries:
                    if archive_saved and status_data is not None:
                        error = TransferError(f"作业文件已保存，但监控日志提交失败：{error.message}", error.status, error.retryable)
                    emit("failed", done, 0, error.message)
                    raise error
                delay = min(retry_delay * 2 ** (attempt - 1), 30)
                emit("retrying", 0, 0, f"{error.message} 将在 {delay:g} 秒后重试（{attempt}/{retries}）。")
                if cancel.wait(delay):
                    raise UploadCancelled()
    except UploadCancelled as exc:
        emit("cancelled", done, 0, exc.message)
        raise
    except OSError as exc:
        raise TransferError("无法读取所选文件，请检查文件权限和磁盘状态。") from exc


def send_archive(ip: str, file_path: str | Path, student_account: str, **options) -> dict:
    """兼容 IP 在前的调用顺序；统一使用 upload_file 实现。"""
    return upload_file(file_path, student_account, ip, **options)


@dataclass(frozen=True)
class UploadJob:
    file_path: str | Path
    student_account: str
    receiver_ip: str
    status_file: str | Path | None = None
    session_token: str | None = field(default=None, repr=False)


def upload_files(jobs: Iterable[UploadJob], *, max_workers: int = 4, port: int = PORT,
                 retries: int = 2, retry_delay: float = 1.0,
                 progress: Callable[[Progress], None] | None = None,
                 cancel: threading.Event | None = None) -> list[dict]:
    """并发上传多个文件，返回与 jobs 顺序一致的结果；单项失败不影响其他项。

    每项成功返回接收确认，失败返回 ok=False、学号、文件名、中文错误。
    progress 会由多个工作线程并发调用；共享 cancel 事件可取消整批。
    """
    if type(max_workers) is not int or not 1 <= max_workers <= MAX_CONNECTIONS:
        raise TransferError(f"并发数须为 1–{MAX_CONNECTIONS} 的整数。")
    items = list(jobs)
    if any(not isinstance(job, UploadJob) or not isinstance(job.file_path, (str, Path)) for job in items):
        raise TransferError("并发任务须为包含文件路径、学号和教师 IP 的 UploadJob。")
    cancel = cancel or threading.Event()

    def execute(job):
        try:
            return upload_file(job.file_path, job.student_account, job.receiver_ip, port=port,
                               retries=retries, retry_delay=retry_delay, progress=progress, cancel=cancel,
                               status_file=job.status_file, session_token=job.session_token)
        except TransferError as exc:
            return {"ok": False, "student_account": job.student_account,
                    "filename": Path(job.file_path).name, "message": exc.message}

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="archive-upload") as executor:
        try:
            return list(executor.map(execute, items))
        except KeyboardInterrupt:
            cancel.set()
            raise



logger = logging.getLogger(__name__)


class ReceiverServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False
    request_queue_size = 128

    def __init__(self, save_dir: str | Path, host: str = "0.0.0.0", port: int = PORT,
                 progress: Callable[[Progress], None] | None = None,
                 accounts_db: str | Path = DEFAULT_DB):
        self.accounts = AccountDatabase(accounts_db)
        self.auth = Authenticator(self.accounts)
        self.storage = SafeStorage(Path(save_dir))
        self.progress_callback = progress
        self.stopping = threading.Event()
        self.serving = threading.Event()
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.connections = set()
        self.connections_lock = threading.Lock()
        self.registry_lock = threading.Lock()
        self.activity_locks = {}
        self.active_uploads = {}
        self.completed_uploads = OrderedDict()
        super().__init__((host, port), _Handler)

    def save_activity(self, submission: Submission, activity: dict, status_sha256: str) -> Path:
        """一个学号一个日志；合并、原子保存成功后再清理旧的按提交编号命名的文件。"""
        from monitoring import (
            MAX_STORED_STATUS_BYTES, MonitorError, merge_status_histories, set_hidden,
            utc_now, validate_status_bytes,
        )
        with self.registry_lock:
            lock = self.activity_locks.setdefault(submission.student_account, threading.Lock())
        storage = self.storage
        directory = storage.checked_path(storage.root / submission.student_account)
        filename = f".programming-status-{submission.student_account}.json"
        target = storage.checked_path(directory / filename)
        with lock:
            histories, receipts, legacy_files = [], {}, []
            sources = [target] if target.exists() else []
            for path in sorted(directory.glob(".programming-status-*.json")):
                if path != target and re.fullmatch(r"\.programming-status-[0-9a-f]{32}\.json", path.name):
                    sources.append(storage.checked_path(path))
            try:
                for path in sources:
                    with path.open("rb") as stream:
                        raw = stream.read(MAX_STORED_STATUS_BYTES + 1)
                    if not raw or len(raw) > MAX_STORED_STATUS_BYTES:
                        raise MonitorError("教师端已有监控日志为空或超过 64 MB。")
                    document = json.loads(raw)
                    if not isinstance(document, dict):
                        raise MonitorError("教师端已有监控日志格式无效。")
                    if document.get("schema") == ACTIVITY_LOG_SCHEMA:
                        if (set(document) != {"schema", "student_account", "activity", "submissions"}
                                or document["student_account"] != submission.student_account
                                or not isinstance(document["submissions"], list) or not document["submissions"]):
                            raise MonitorError("教师端已有监控汇总字段无效。")
                        records = document["submissions"]
                    else:
                        if set(document) != {"submission", "received_at", "status_sha256", "activity"}:
                            raise MonitorError("教师端已有监控日志字段无效。")
                        records = [{key: document[key] for key in ("submission", "received_at", "status_sha256")}]
                    encoded_activity = json.dumps(document["activity"], ensure_ascii=False).encode("utf-8")
                    histories.append(validate_status_bytes(encoded_activity, submission.student_account,
                                                           max_bytes=MAX_STORED_STATUS_BYTES))
                    for record in records:
                        if not isinstance(record, dict) or set(record) != {"submission", "received_at", "status_sha256"}:
                            raise MonitorError("教师端已有提交记录字段无效。")
                        metadata = Submission(**record["submission"])
                        metadata.validate()
                        if metadata.student_account != submission.student_account:
                            raise MonitorError("教师端已有日志学号不匹配。")
                        if (not isinstance(record["status_sha256"], str)
                                or not re.fullmatch(r"[0-9a-f]{64}", record["status_sha256"])
                                or not isinstance(record["received_at"], str)
                                or datetime.fromisoformat(record["received_at"]).tzinfo is None):
                            raise MonitorError("教师端已有提交确认信息无效。")
                        previous = receipts.get(metadata.upload_id)
                        if previous and previous["submission"] != record["submission"]:
                            raise MonitorError("教师端已有提交编号的文件信息不一致。")
                        if previous is None or datetime.fromisoformat(record["received_at"]) > datetime.fromisoformat(previous["received_at"]):
                            receipts[metadata.upload_id] = record
                    if path != target:
                        legacy_files.append((path, hashlib.sha256(raw).hexdigest()))
                histories.append(activity)
                combined = merge_status_histories(histories, submission.student_account)
                validate_status_bytes(json.dumps(combined, ensure_ascii=False).encode("utf-8"),
                                      submission.student_account, max_bytes=MAX_STORED_STATUS_BYTES)
            except (MonitorError, TransferError, ValueError, TypeError, KeyError, RecursionError) as exc:
                raise TransferError(f"监控历史合并失败，已有日志已保留：{exc}") from exc
            receipt = {"submission": asdict(submission), "received_at": utc_now(), "status_sha256": status_sha256}
            previous = receipts.get(submission.upload_id)
            if previous and previous["submission"] != receipt["submission"]:
                raise TransferError("已有日志中的提交编号与本次文件信息不一致。")
            receipts[submission.upload_id] = receipt
            envelope = dict(schema=ACTIVITY_LOG_SCHEMA, student_account=submission.student_account,
                            activity=combined, submissions=sorted(receipts.values(), key=lambda record: datetime.fromisoformat(record["received_at"])))
            encoded = json.dumps(envelope, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
            if len(encoded) > MAX_STORED_STATUS_BYTES:
                raise TransferError("教师端汇总日志超过 64 MB，已有日志已保留。", 413)
            temporary = storage.checked_path(directory / f".{uuid.uuid4().hex}.uploading")
            try:
                with temporary.open("xb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                set_hidden(temporary)
                target = storage.commit(temporary, filename)
            finally:
                temporary.unlink(missing_ok=True)
            for path, digest in legacy_files:
                try:
                    storage.checked_path(path)
                    # 如果外部程序在合并过程中更新旧文件，保留它供下次再合并。
                    with path.open("rb") as stream:
                        current = stream.read(MAX_STORED_STATUS_BYTES + 1)
                    if hmac.compare_digest(hashlib.sha256(current).hexdigest(), digest):
                        path.unlink()
                except (OSError, TransferError):
                    logger.warning("汇总已保存，旧日志暂未清理：%s", path.name)
            return target

    def submission_status(self, submission: Submission) -> dict:
        with self.registry_lock:
            completed = self.completed_uploads.get(submission.upload_id)
            if completed:
                previous, receipt = completed
                if previous != submission:
                    raise TransferError("提交编号与原文件信息不一致。", 409)
                self.completed_uploads.move_to_end(submission.upload_id)
                return {**receipt, "state": "completed"}
            active = self.active_uploads.get(submission.upload_id)
            if active:
                if active != submission:
                    raise TransferError("提交编号与正在接收的文件不一致。", 409)
                return {"ok": True, "state": "receiving"}
            return {"ok": True, "state": "ready"}

    def claim_submission(self, submission: Submission) -> dict | None:
        with self.registry_lock:
            completed = self.completed_uploads.get(submission.upload_id)
            if completed:
                previous, receipt = completed
                if previous != submission:
                    raise TransferError("提交编号与原文件信息不一致。", 409)
                return dict(receipt)
            active = self.active_uploads.get(submission.upload_id)
            if active:
                if active != submission:
                    raise TransferError("提交编号与正在接收的文件不一致。", 409)
                raise TransferError("同一次提交仍在接收，请稍后重试。", 409, True)
            self.active_uploads[submission.upload_id] = submission
            return None

    def complete_submission(self, submission: Submission, receipt: dict):
        with self.registry_lock:
            self.completed_uploads[submission.upload_id] = (submission, dict(receipt))
            self.completed_uploads.move_to_end(submission.upload_id)
            while len(self.completed_uploads) > 4096:
                self.completed_uploads.popitem(last=False)

    def release_submission(self, submission: Submission):
        with self.registry_lock:
            self.active_uploads.pop(submission.upload_id, None)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(0.5)
        with self.connections_lock:
            self.connections.add(connection)
        return connection, address

    def shutdown_request(self, request):
        with self.connections_lock:
            self.connections.discard(request)
        super().shutdown_request(request)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            body = json.dumps({"ok": False, "message": "教师端连接较多，请稍后重新提交。"}, ensure_ascii=False).encode("utf-8")
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: "
                                + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
                # Drain a bounded amount of pending request data so Windows
                # does not replace the already-sent 503 with a TCP reset.
                request.shutdown(socket.SHUT_WR)
                request.settimeout(0.2)
                remaining = 16384
                deadline = time.monotonic() + 0.2
                while remaining and time.monotonic() < deadline:
                    data = request.recv(min(4096, remaining))
                    if not data:
                        break
                    remaining -= len(data)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def serve_forever(self, poll_interval=0.1):
        self.serving.set()
        try:
            super().serve_forever(poll_interval)
        finally:
            self.serving.clear()

    def stop(self):
        """从服务循环以外的线程调用；关闭活动连接以触发临时文件清理。"""
        self.stopping.set()
        # Stop accepting before snapshotting active sockets so none can be missed.
        if self.serving.is_set():
            self.shutdown()
        with self.connections_lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self.stop()
        self.server_close()  # joins workers, including each worker's finally cleanup

    def notify(self, event: Progress):
        if self.progress_callback:
            try:
                self.progress_callback(event)
            except Exception:
                logger.exception("接收进度回调失败")


class _CancellableReader(io.RawIOBase):
    """Poll cancellation without poisoning socket.makefile after a timeout."""

    def __init__(self, connection, server):
        super().__init__()
        self.connection, self.server = connection, server
        self.last_data = time.monotonic()

    def readable(self):
        return True

    def readinto(self, buffer):
        while True:
            if self.server.stopping.is_set():
                raise TimeoutError("receiver stopping")
            try:
                count = self.connection.recv_into(buffer)
                if count:
                    self.last_data = time.monotonic()
                return count
            except socket.timeout:
                if time.monotonic() - self.last_data >= IDLE_TIMEOUT:
                    raise TimeoutError("upload idle timeout")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LANArchive/3"
    sys_version = ""

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(_CancellableReader(self.connection, self.server))

    def log_message(self, fmt, *args):
        # 请求行可能包含恶意输入；日志不记录请求内容或认证头。
        logger.debug("教师端请求，来源：%s", self.client_address[0])

    def reply(self, status: int, fields: dict):
        body = json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        # A connection carries one request; unread rejected payloads are discarded.
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        if self.command == "POST" and status >= 400:
            # Deliver the rejection before closing a socket with unread body
            # bytes. Otherwise Windows may discard the JSON response on reset.
            try:
                self.connection.shutdown(socket.SHUT_WR)
                self.connection.settimeout(0.1)
                remaining = CHUNK_SIZE
                deadline = time.monotonic() + 0.2
                while remaining and time.monotonic() < deadline:
                    chunk = self.connection.recv(min(32768, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
            except OSError:
                pass

    def do_GET(self):
        try:
            if self.server.stopping.is_set():
                raise TransferError("教师已停止接收。", 503)
            if self.path == "/health":
                try:
                    import monitoring
                    features = [STATUS_FEATURE]
                    if hasattr(monitoring, "HISTORY_SCHEMA"):
                        features.append(HISTORY_FEATURE)
                except ImportError:
                    features = []
                features.append(AUTH_FEATURE)
                self.reply(200, {"ok": True, "protocol": PROTOCOL, "port": self.server.server_port,
                                 "features": features, "authentication_required": True})
            elif self.path == "/status":
                values = self.headers.get_all(METADATA_HEADER, [])
                if len(values) != 1:
                    raise TransferError("提交信息缺失或重复。")
                submission = Submission.decode(values[0])
                self.require_auth(submission.student_account)
                self.reply(200, self.server.submission_status(submission))
            else:
                raise TransferError("接口不存在。", 404)
        except TransferError as exc:
            self.reply_safely(exc.status, exc.message, exc.retryable)
        except AccountError as exc:
            self.reply_safely(exc.status, str(exc))
        except sqlite3.Error:
            self.reply_safely(503, "账号数据库暂时不可用，请联系教师。")
        except OSError:
            self.close_connection = True

    def read_token(self) -> str:
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1 or not re.fullmatch(r"Bearer [A-Za-z0-9_-]{43}", values[0]):
            raise TransferError("请先使用正确的账号密码登录学生端。", 401)
        return values[0][7:]

    def require_auth(self, account: str | None = None):
        return self.server.auth.authorize(self.read_token(), account)

    def receive_auth(self):
        try:
            if self.server.stopping.is_set():
                raise TransferError("教师已停止接收。", 503)
            if self.path == "/auth/logout":
                self.server.auth.logout(self.read_token())
                self.reply(200, {"ok": True, "message": "已退出登录"})
                return
            if self.headers.get_all("Content-Type", []) != ["application/json; charset=utf-8"]:
                raise TransferError("登录信息须为 UTF-8 JSON。")
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or not re.fullmatch(r"[1-9][0-9]{0,3}", lengths[0])
                    or int(lengths[0]) > 4096):
                raise TransferError("登录信息长度无效。")
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"):
                raise TransferError("不支持此登录传输编码。")
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise TransferError("登录信息不完整。")
            try:
                fields = json.loads(raw)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise TransferError("登录信息格式无效。") from exc
            expected = {"student_account", "password"} if self.path == "/auth/login" else {"old_password", "new_password"}
            if not isinstance(fields, dict) or set(fields) != expected:
                raise TransferError("登录信息字段无效。")
            if self.path == "/auth/login":
                result = self.server.auth.login(fields["student_account"], fields["password"])
            else:
                account = self.require_auth()
                self.server.accounts.change_password(account, fields["old_password"], fields["new_password"])
                result = {"ok": True, "message": "密码修改成功，请使用新密码重新登录。"}
            self.reply(200, result)
        except (AccountError, TransferError) as exc:
            self.reply_safely(exc.status, str(exc))
        except sqlite3.Error:
            self.reply_safely(503, "账号数据库暂时不可用，请联系教师。")
        except OSError:
            self.reply_safely(408, "登录连接中断，请重试。")
        except Exception:
            # 不输出认证请求或局部变量，避免泄露密码。
            self.reply_safely(500, "教师端身份验证失败，请联系教师。")

    def read_submission(self) -> Submission:
        values = self.headers.get_all(METADATA_HEADER, [])
        if len(values) != 1:
            raise TransferError("提交信息缺失或重复。")
        submission = Submission.decode(values[0])
        if self.headers.get_all("Content-Type", []) != ["application/octet-stream"]:
            raise TransferError("传输类型错误，请提交原始压缩文件。")
        if self.headers.get_all("Content-Length", []) != [str(submission.size)]:
            raise TransferError("文件长度参数不一致，已拒绝提交。")
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"):
            raise TransferError("不支持此传输编码，请使用发送脚本。")
        return submission

    def do_POST(self):
        if self.path in ("/auth/login", "/auth/logout", "/auth/change-password"):
            self.receive_auth()
            return
        if self.path == "/activity":
            self.receive_activity()
            return
        sink, submission, claimed = None, None, False
        task_id = uuid.uuid4().hex
        speed_time = last_emit = time.monotonic()
        speed_bytes, speed = 0, 0.0

        def emit(phase, status, saved_path=""):
            if submission:
                self.server.notify(Progress(phase, sink.received if sink else 0, submission.size, speed,
                                            status, task_id=task_id, student_account=submission.student_account,
                                            filename=submission.filename, saved_path=saved_path, attempt=0))

        try:
            if self.path != "/upload":
                raise TransferError("接口不存在。", 404)
            if self.server.stopping.is_set():
                raise TransferError("教师已停止接收。", 503)
            submission = self.read_submission()
            self.require_auth(submission.student_account)
            task_id = submission.upload_id
            completed = self.server.claim_submission(submission)
            if completed:
                self.reply(200, completed)
                return
            claimed = True
            sink = self.server.storage.begin(submission)
            emit("receiving", "正在接收")
            while sink.received < submission.size:
                if self.server.stopping.is_set():
                    raise TransferError("教师已停止接收，未完成上传已中止。", 503)
                chunk = self.rfile.read(min(CHUNK_SIZE, submission.size - sink.received))
                if not chunk:
                    raise TransferError("网络连接中断，文件传输不完整，请重新提交。", 408)
                sink.write(chunk)
                now = time.monotonic()
                if now - speed_time >= 0.2 or sink.received == submission.size:
                    speed = (sink.received - speed_bytes) / max(now - speed_time, 0.001)
                    speed_time, speed_bytes = now, sink.received
                if now - last_emit >= 0.1:
                    emit("receiving", "正在接收")
                    last_emit = now
            if self.server.stopping.is_set():
                raise TransferError("教师已停止接收，未完成上传已中止。", 503)
            emit("verifying", "正在校验并保存")
            target = sink.finish()
            receipt = {"ok": True, "message": "作业提交成功", "filename": target.name,
                       "student_account": submission.student_account, "upload_id": submission.upload_id,
                       "size": sink.received, "sha256": sink.digest.hexdigest()}
            self.server.complete_submission(submission, receipt)
            emit("done", "接收成功", str(target))
            self.reply(200, receipt)
        except TransferError as exc:
            emit("failed", exc.message)
            self.reply_safely(exc.status, exc.message, exc.retryable)
        except AccountError as exc:
            emit("failed", str(exc))
            self.reply_safely(exc.status, str(exc))
        except sqlite3.Error:
            self.reply_safely(503, "账号数据库暂时不可用，请联系教师。")
        except TimeoutError:
            stopped = self.server.stopping.is_set()
            message = "教师已停止接收，未完成上传已中止。" if stopped else "超过 120 秒未收到数据，上传已中止，请重新提交。"
            emit("failed", message)
            self.reply_safely(503 if stopped else 408, message)
        except OSError as exc:
            # A lost acknowledgement cannot undo an already verified saved file.
            if sink and sink.completed:
                logger.info("作业已保存，但无法回传确认：%s", submission.filename)
            else:
                error = (TransferError("网络连接中断，请重新提交。", 408)
                         if isinstance(exc, ConnectionError) else disk_error(exc))
                emit("failed", error.message)
                self.reply_safely(error.status, error.message)
        except Exception:
            logger.exception("接收任务异常")
            emit("failed", "接收失败，请重新提交或联系教师")
            self.reply_safely(500, "教师端接收失败，请重新提交或联系教师。")
        finally:
            try:
                if sink:
                    sink.abort()
            except OSError:
                logger.exception("临时文件清理失败；文件仍以 .uploading 命名")
            finally:
                if claimed:
                    self.server.release_submission(submission)

    def receive_activity(self):
        """内部辅助日志接口：只能绑定已完成、信息完全匹配的 ZIP/RAR 提交。"""
        saved = False
        try:
            from monitoring import MAX_STATUS_BYTES, MonitorError, validate_status_bytes
            if self.server.stopping.is_set():
                raise TransferError("教师已停止接收。", 503, True)
            values = self.headers.get_all(METADATA_HEADER, [])
            if len(values) != 1:
                raise TransferError("监控日志缺少有效的作业提交信息。")
            submission = Submission.decode(values[0])
            self.require_auth(submission.student_account)
            state = self.server.submission_status(submission)
            if state.get("state") != "completed":
                raise TransferError("对应作业尚未完整保存，不能接收其监控日志。", 409, True)
            if self.headers.get_all("Content-Type", []) != ["application/json; charset=utf-8"]:
                raise TransferError("监控日志必须为 UTF-8 JSON。")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not re.fullmatch(r"[1-9][0-9]{0,7}", lengths[0]):
                raise TransferError("监控日志长度无效。")
            length = int(lengths[0])
            if length > MAX_STATUS_BYTES:
                raise TransferError(f"监控历史不能超过 {format_size(MAX_STATUS_BYTES)}。", 413)
            hashes = self.headers.get_all(STATUS_HASH_HEADER, [])
            if len(hashes) != 1 or not re.fullmatch(r"[0-9a-f]{64}", hashes[0]):
                raise TransferError("监控日志 SHA256 无效。")
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"):
                raise TransferError("不支持此监控日志传输编码。")
            data = self.rfile.read(length)
            if len(data) != length:
                raise TransferError("监控日志传输中断，请重新提交。", 408, True)
            status_sha256 = hashlib.sha256(data).hexdigest()
            if not hmac.compare_digest(status_sha256, hashes[0]):
                raise TransferError("监控日志 SHA256 校验失败。", 422, True)
            try:
                activity = validate_status_bytes(data, submission.student_account)
            except MonitorError as exc:
                raise TransferError(str(exc)) from exc
            target = self.server.save_activity(submission, activity, status_sha256)
            saved = True
            self.server.notify(Progress("status", submission.size, submission.size, 0,
                                        "监控日志已保存", task_id=submission.upload_id,
                                        student_account=submission.student_account, filename=submission.filename,
                                        saved_path=str(target), attempt=0))
            self.reply(200, {"ok": True, "message": "监控日志提交成功", "upload_id": submission.upload_id,
                             "student_account": submission.student_account, "status_filename": target.name,
                             "status_sha256": status_sha256})
        except TransferError as exc:
            self.reply_safely(exc.status, exc.message, exc.retryable)
        except AccountError as exc:
            self.reply_safely(exc.status, str(exc))
        except sqlite3.Error:
            self.reply_safely(503, "账号数据库暂时不可用，请联系教师。")
        except TimeoutError:
            self.reply_safely(408, "监控日志接收超时，请重新提交。", True)
        except OSError as exc:
            if saved:
                logger.info("监控日志已保存，但无法回传确认")
            else:
                error = disk_error(exc)
                self.reply_safely(error.status, error.message, isinstance(exc, ConnectionError))
        except Exception:
            logger.exception("接收监控日志失败")
            self.reply_safely(500, "教师端接收监控日志失败，请联系教师。")
    def reply_safely(self, status, message, retryable=False):
        try:
            self.reply(status, {"ok": False, "message": message, "retryable": retryable})
        except OSError:
            self.close_connection = True


_console_lock = threading.Lock()


def _show_progress(event: Progress):
    label = "已校验" if event.phase == "hashing" else "已接收" if event.phase == "receiving" else "已发送"
    attempt = f"第{event.attempt}次 | " if event.attempt else ""
    with _console_lock:
        print(f"[{event.student_account}] {event.filename} | {attempt}{event.percentage:6.2f}% | "
              f"{label} {format_size(event.done)} / {format_size(event.total)} | {format_size(event.speed)}/s | {event.status}", flush=True)
        if event.saved_path:
            print(f"  已保存：{event.saved_path}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="ZIP / RAR 作业上传：流式、并发、重试、按学号归档")
    commands = parser.add_subparsers(dest="command", required=True)
    receive = commands.add_parser("receive", help="在教师电脑启动接收")
    receive.add_argument("--save-dir", required=True, help="保存目录，每个学号使用一个子目录")
    receive.add_argument("--accounts-db", default=str(DEFAULT_DB), help="教师本地学生账号库路径")
    send = commands.add_parser("send", help="上传一个或多个压缩文件")
    send.add_argument("--ip", required=True, help="教师电脑 IPv4")
    send.add_argument("--student-account", "--student-id", dest="student_account", required=True, help="学生学号")
    send.add_argument("--file", action="append", required=True, help=".zip / .rar 文件路径，可重复填写以并发上传")
    send.add_argument("--workers", type=int, default=4, help="多文件并发数，默认 4")
    send.add_argument("--retries", type=int, default=2, help="失败后的重试次数，默认 2")
    send.add_argument("--retry-delay", type=float, default=1.0, help="首次重试间隔秒数，后续翻倍，默认 1")
    send.add_argument("--status-file", help="显式指定监控日志；默认自动附带该学号在 student_status 下的日志")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
    server = None
    session = None
    try:
        if args.command == "receive":
            server = ReceiverServer(args.save_dir, progress=_show_progress, accounts_db=args.accounts_db)
            addresses = local_ipv4_addresses()
            print("教师电脑 IPv4：" + (" / ".join(addresses) if addresses else "未检测到，请通过 ipconfig 查看"))
            print(f"固定端口：{PORT}\n保存目录：{server.storage.root}\n已开始接收，按 Ctrl+C 停止。", flush=True)
            print(f"学生账号库：{server.accounts.path}\n已启用账号密码验证。", flush=True)
            if not server.accounts.list_students():
                print("账号库为空，请先在教师电脑运行 python accounts.py add --student-account 学号 创建账号。", flush=True)
            server.serve_forever()
            return 0
        validate_student_account(args.student_account)
        status_file = Path(args.status_file) if args.status_file else None
        if status_file is None:
            candidate = Path(__file__).resolve().parent / "student_status" / f".programming-status-{args.student_account}.json"
            if candidate.is_file():
                status_file = candidate
        if status_file is not None:
            print(f"将随作业提交软件使用与告警日志：{status_file}", flush=True)
        import getpass
        password = getpass.getpass("学生账号密码：")
        session = login_student(args.ip, args.student_account, password)
        del password
        options = dict(retries=args.retries, retry_delay=args.retry_delay, progress=_show_progress)
        if len(args.file) == 1:
            results = [upload_file(args.file[0], args.student_account, args.ip, status_file=status_file,
                                   session_token=session["token"], **options)]
        else:
            jobs = [UploadJob(path, args.student_account, args.ip, status_file, session["token"]) for path in args.file]
            results = upload_files(jobs, max_workers=args.workers, **options)
        for result in results:
            print(f"{result['filename']}：" + ("作业提交成功" if result["ok"] else result["message"]), flush=True)
        return 0 if all(result["ok"] for result in results) else 1
    except TransferError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    except (AccountError, sqlite3.Error):
        print("账号数据库无法打开，请检查教师端数据库路径、权限和版本。", file=sys.stderr)
        return 1
    except EOFError:
        print("未输入密码，已取消上传。", file=sys.stderr)
        return 1
    except OSError:
        print("启动接收失败：请检查保存目录权限及端口 9000 是否被占用。", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已停止操作，正在清理未完成的上传…", flush=True)
        return 130
    finally:
        if server:
            server.close()
        if session is not None:
            try:
                logout_student(args.ip, session["token"])
            except TransferError:
                pass  # 网络中断时令牌只能等待到期；本进程不再保留令牌。


if __name__ == "__main__":
    sys.exit(main())
