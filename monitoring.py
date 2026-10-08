"""学生明确启用的软件使用监控：统计次数，浏览器和 USB 存储设备只告警。

python monitoring.py --student-account 20260001
python monitoring.py --student-account 20260001 --agree
按 Ctrl+C 停止。默认统计全部前台软件；--apps 可限制统计范围，浏览器仍告警。
日志包含登录时间、电脑信息、学生 IP、进程统计、浏览器告警和 USB 盘符。
同一学号的历次监控按 sessions 顺序累积保存，运行中只更新当前会话。
不保存具体按键、窗口标题、网址、搜索词、网页正文或 U 盘文件。
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
import ipaddress
import math
import os
from pathlib import Path
import platform
import queue
import re
import socket
import struct
import sys
import threading
import time
import uuid


LEGACY_SCHEMA = "lan-programming-status/1"
SCHEMA = "lan-programming-status/2"
HISTORY_SCHEMA = "lan-programming-status-history/1"
MAX_SESSION_BYTES = 512 * 1024
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_APPS = 512
MAX_EVENTS = 200
BROWSERS = frozenset({"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
                      "vivaldi.exe", "iexplore.exe", "qqbrowser.exe", "360chrome.exe",
                      "360se.exe", "sogouexplorer.exe"})
NOTICE = ("课堂监控将重点检测并告警：前台浏览器使用，以及 USB 存储设备连接。"
          "同时统计前台软件名称、使用时长和按键/鼠标事件次数；"
          "每次监控还会记录登录时间、电脑名称、系统版本和学生电脑 IP，"
          "按学号保留历次监控日志，并随作业提交给教师。")


class MonitorError(ValueError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def collect_device_info(receiver_ip: str | None = None) -> tuple[dict, str | None]:
    """优先取得通往教师电脑的本机 IPv4；UDP connect 仅查询路由，不发送数据。"""
    device = dict(hostname=socket.gethostname(), system=platform.system(),
                  system_version=platform.version(), architecture=platform.machine())
    if receiver_ip:
        try:
            target = str(ipaddress.IPv4Address(receiver_ip))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.connect((target, 9000))
                return device, connection.getsockname()[0]
        except (OSError, ValueError):
            pass
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
        addresses = {value for value in addresses if not ipaddress.IPv4Address(value).is_loopback
                     and not ipaddress.IPv4Address(value).is_link_local and value != "0.0.0.0"}
        ordered = sorted(addresses, key=lambda value: (not ipaddress.IPv4Address(value).is_private,
                                                       int(ipaddress.IPv4Address(value))))
        return device, ordered[0] if ordered else None
    except OSError:
        return device, None


def check_account(account: str):
    if not isinstance(account, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", account):
        raise MonitorError("学号须为 1–32 位数字、英文字母、下划线或短横线。")
    if re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", account, re.I):
        raise MonitorError("学号不能使用 Windows 保留名称。")


def check_process(name):
    if (not isinstance(name, str) or not 1 <= len(name) <= 160 or name != name.strip()
            or any(ord(c) < 32 or c in '<>:"/\\|?*' for c in name) or name in (".", "..")):
        raise MonitorError("日志中的软件进程名无效。")


def default_status_path(account: str, directory: str | Path | None = None) -> Path:
    check_account(account)
    root = Path(directory) if directory is not None else Path(__file__).resolve().parent / "student_status"
    return root / f".programming-status-{account}.json"


def set_hidden(path: Path):
    if os.name != "nt":
        return
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel.GetFileAttributesW.restype = wintypes.DWORD
    kernel.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel.SetFileAttributesW.restype = wintypes.BOOL
    attributes = kernel.GetFileAttributesW(str(path))
    if attributes == 0xFFFFFFFF or not kernel.SetFileAttributesW(str(path), (attributes & ~0x80) | 2):
        raise ctypes.WinError(ctypes.get_last_error())


def atomic_hidden_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{uuid.uuid4().hex}.uploading"
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        set_hidden(temporary)
        # Windows 上提交线程可能正在读取上一份快照，等待短暂的共享占用结束。
        for attempt in range(11):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 10:
                    raise
                time.sleep(0.05)
    finally:
        temporary.unlink(missing_ok=True)


def _number(value, label, integer=False):
    if (type(value) not in ((int,) if integer else (int, float))
            or not math.isfinite(value) or not 0 <= value <= 10**12):
        raise MonitorError(f"日志中的{label}无效。")


def _date(value):
    if not isinstance(value, str) or len(value) > 40:
        raise MonitorError("日志时间无效。")
    try:
        if datetime.fromisoformat(value).tzinfo is None:
            raise ValueError()
    except ValueError as exc:
        raise MonitorError("日志时间必须包含时区。") from exc


def validate_status_bytes(data: bytes, account: str) -> dict:
    check_account(account)
    if not 0 < len(data) <= MAX_STATUS_BYTES:
        raise MonitorError("监控日志为空或超过 16 MB；已有历史不会被自动删除。")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise MonitorError("监控日志不是有效的 UTF-8 JSON。") from exc
    if isinstance(value, dict) and value.get("schema") == HISTORY_SCHEMA:
        if set(value) != {"schema", "student_account", "sessions"} or value["student_account"] != account:
            raise MonitorError("监控历史字段或学号不匹配。")
        sessions = value["sessions"]
        if not isinstance(sessions, list) or not sessions:
            raise MonitorError("监控历史必须包含会话记录。")
        seen = set()
        for session in sessions:
            _validate_session(session, account)
            if session["session_id"] in seen:
                raise MonitorError("监控历史中存在重复的会话编号。")
            seen.add(session["session_id"])
        return value
    return _validate_session(value, account)


def _validate_session(value: dict, account: str) -> dict:
    fields = {"schema", "student_account", "session_id", "started_at", "updated_at", "state",
              "consent", "scope", "sample_interval_seconds", "idle_threshold_seconds", "duration_seconds",
              "applications", "browser_events", "usb_events", "dropped_browser_events", "dropped_usb_events",
              "dropped_input_events", "sampling_gaps", "current_process", "error"}
    if not isinstance(value, dict):
        raise MonitorError("监控会话必须为 JSON 对象。")
    if value.get("schema") == SCHEMA:
        fields.update({"login_at", "device", "ip"})
    if set(value) != fields:
        raise MonitorError("监控日志字段无效。")
    if (value["schema"] not in (LEGACY_SCHEMA, SCHEMA) or value["student_account"] != account or value["consent"] is not True
            or value["scope"] != "foreground_counts_browser_usb_warn_only"):
        raise MonitorError("监控日志版本、学号或知情启用标记不匹配。")
    if not isinstance(value["session_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["session_id"]):
        raise MonitorError("监控会话编号无效。")
    if value["state"] not in ("running", "stopped", "error"):
        raise MonitorError("监控状态无效。")
    for name in ("started_at", "updated_at"):
        _date(value[name])
    if value["schema"] == SCHEMA:
        _date(value["login_at"])
        device = value["device"]
        if not isinstance(device, dict) or set(device) != {"hostname", "system", "system_version", "architecture"}:
            raise MonitorError("登录设备信息字段无效。")
        for item in device.values():
            if not isinstance(item, str) or len(item) > 256 or any(ord(char) < 32 for char in item):
                raise MonitorError("登录设备信息无效。")
        if value["ip"] is not None:
            try:
                if not isinstance(value["ip"], str):
                    raise ValueError()
                address = ipaddress.IPv4Address(value["ip"])
                if address.is_unspecified or address.is_multicast or address.is_reserved:
                    raise ValueError()
            except ValueError as exc:
                raise MonitorError("登录设备 IP 无效。") from exc
    for name in ("sample_interval_seconds", "idle_threshold_seconds", "duration_seconds"):
        _number(value[name], name)
    for name in ("dropped_browser_events", "dropped_usb_events", "dropped_input_events", "sampling_gaps"):
        _number(value[name], name, True)
    if not isinstance(value["error"], str) or len(value["error"]) > 240:
        raise MonitorError("监控错误说明无效。")
    if value["current_process"] is not None:
        check_process(value["current_process"])
    apps = value["applications"]
    if not isinstance(apps, list) or len(apps) > MAX_APPS:
        raise MonitorError("软件统计数量无效。")
    app_fields = {"process_name", "foreground_seconds", "active_seconds", "keyboard_events", "mouse_clicks",
                  "wheel_events", "focus_switches", "operations_per_minute"}
    seen = set()
    for app in apps:
        if not isinstance(app, dict) or set(app) != app_fields:
            raise MonitorError("软件统计字段无效。")
        check_process(app["process_name"])
        if app["process_name"] in seen:
            raise MonitorError("软件统计存在重复项。")
        seen.add(app["process_name"])
        for key in ("foreground_seconds", "active_seconds", "operations_per_minute"):
            _number(app[key], key)
        if app["active_seconds"] > app["foreground_seconds"] + 0.01:
            raise MonitorError("有效操作时长不能超过前台时长。")
        for key in ("keyboard_events", "mouse_clicks", "wheel_events", "focus_switches"):
            _number(app[key], key, True)
    for key, kind in (("browser_events", "browser_foreground"), ("usb_events", "usb_storage_connected")):
        events = value[key]
        if not isinstance(events, list) or len(events) > MAX_EVENTS:
            raise MonitorError("告警事件数量无效。")
        for event in events:
            event_fields = {"at", "kind", "action", "process_name" if key == "browser_events" else "drive"}
            if not isinstance(event, dict) or set(event) != event_fields or event["kind"] != kind or event["action"] != "warned":
                raise MonitorError("告警事件字段无效。")
            _date(event["at"])
            if key == "browser_events":
                check_process(event["process_name"])
            elif not isinstance(event["drive"], str) or not re.fullmatch(r"[A-Z]:\\", event["drive"]):
                raise MonitorError("USB 盘符无效。")
    return value


def read_status_file(path: str | Path, account: str) -> bytes:
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_STATUS_BYTES + 1)
    validate_status_bytes(data, account)
    return data


class UsageSession:
    """可独立测试的统计器；所有数值汇总，不保存具体输入事件内容。"""

    def __init__(self, account, interval=0.5, idle_threshold=60, apps=None, browsers=None, warning=None,
                 *, login_at=None, device=None, ip=None):
        check_account(account)
        self.account, self.interval, self.idle_threshold = account, interval, idle_threshold
        self.allowed = {name.lower() for name in apps} if apps else None
        self.browsers = BROWSERS | {name.lower() for name in (browsers or [])}
        self.warning = warning or (lambda message: None)
        self.lock = threading.RLock()
        self.session_id, self.started_at = uuid.uuid4().hex, utc_now()
        self.login_at = login_at or self.started_at
        self.device = device if device is not None else collect_device_info()[0]
        self.ip = ip
        self.started = self.last_sample = time.monotonic()
        self.current = None
        self.state, self.error = "running", ""
        self.applications, self.browser_events, self.usb_events = {}, [], []
        self.last_warning, self.usb_drives = {}, set()
        self.dropped_browser_events = self.dropped_usb_events = self.sampling_gaps = 0

    def _app(self, name):
        if name is None:
            return None
        name = name.lower()
        if self.allowed is not None and name not in self.allowed and name not in self.browsers:
            return None
        if name not in self.applications and len(self.applications) < MAX_APPS:
            self.applications[name] = dict(process_name=name, foreground_seconds=0.0, active_seconds=0.0,
                                           keyboard_events=0, mouse_clicks=0, wheel_events=0, focus_switches=0,
                                           operations_per_minute=0.0)
        return self.applications.get(name)

    def operation(self, name, kind):
        with self.lock:
            app = self._app(name)
            if app and kind in ("keyboard_events", "mouse_clicks", "wheel_events"):
                app[kind] += 1

    def sample(self, name, idle_seconds, usb_drives, now=None):
        messages = []
        now = time.monotonic() if now is None else now
        name = name.lower() if name else None
        with self.lock:
            elapsed = max(0.0, now - self.last_sample)
            if elapsed > max(5, self.interval * 5):
                self.sampling_gaps += 1
                elapsed = 0
            previous = self._app(self.current)
            if previous:
                previous["foreground_seconds"] += elapsed
                previous["active_seconds"] += max(0, elapsed - max(0, idle_seconds - self.idle_threshold))
            app = self._app(name)
            if app and name != self.current:
                app["focus_switches"] += 1
            self.current, self.last_sample = name, now
            if name in self.browsers and now - self.last_warning.get(name, -1e12) >= 30:
                self.last_warning[name] = now
                self.browser_events.append(dict(at=utc_now(), kind="browser_foreground", process_name=name, action="warned"))
                if len(self.browser_events) > MAX_EVENTS:
                    self.browser_events.pop(0)
                    self.dropped_browser_events += 1
                messages.append(f"检测到浏览器 {name} 在前台使用，已记录。请按课堂要求完成作业。")
            for drive in sorted(set(usb_drives) - self.usb_drives):
                self.usb_events.append(dict(at=utc_now(), kind="usb_storage_connected", drive=drive, action="warned"))
                if len(self.usb_events) > MAX_EVENTS:
                    self.usb_events.pop(0)
                    self.dropped_usb_events += 1
                messages.append(f"检测到 USB 存储设备连接：{drive}，已记录。请按课堂要求完成作业。")
            self.usb_drives = set(usb_drives)
        for message in messages:
            self.warning(message)

    def snapshot(self, dropped_input_events=0):
        with self.lock:
            apps = []
            for value in self.applications.values():
                app = dict(value)
                operations = sum(app[key] for key in ("keyboard_events", "mouse_clicks", "wheel_events"))
                app["operations_per_minute"] = operations * 60 / app["active_seconds"] if app["active_seconds"] else 0.0
                for key in ("foreground_seconds", "active_seconds", "operations_per_minute"):
                    app[key] = round(app[key], 3)
                apps.append(app)
            return dict(schema=SCHEMA, student_account=self.account, session_id=self.session_id,
                        login_at=self.login_at, device=dict(self.device), ip=self.ip,
                        started_at=self.started_at, updated_at=utc_now(), state=self.state, consent=True,
                        scope="foreground_counts_browser_usb_warn_only", sample_interval_seconds=self.interval,
                        idle_threshold_seconds=self.idle_threshold, duration_seconds=round(time.monotonic() - self.started, 3),
                        applications=sorted(apps, key=lambda app: app["process_name"]),
                        browser_events=list(self.browser_events), usb_events=list(self.usb_events),
                        dropped_browser_events=self.dropped_browser_events, dropped_usb_events=self.dropped_usb_events,
                        dropped_input_events=dropped_input_events, sampling_gaps=self.sampling_gaps,
                        current_process=self.current, error=self.error)

    def encode(self, dropped_input_events=0):
        data = json.dumps(self.snapshot(dropped_input_events), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_SESSION_BYTES:
            raise MonitorError("单次监控日志不能超过 512 KB。")
        validate_status_bytes(data, self.account)
        return data


class WindowsBackend:
    """当前 Windows 会话的前台进程、输入计数和已挂载 USB/可移动盘。"""

    def __init__(self, account):
        if os.name != "nt":
            raise MonitorError("软件使用监控目前仅支持 Windows 10/11。")
        self.account = account
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.events = queue.Queue(maxsize=10000)
        self.dropped_events = 0
        self.process_cache, self.drive_cache = {}, {}
        self.ready = threading.Event()
        self.thread = None
        self.thread_id = 0
        self.error = None
        self.mutex = None
        self.callbacks = None
        self._configure()

    def _configure(self):
        def api(dll, name, arguments, result):
            function = getattr(dll, name)
            function.argtypes, function.restype = arguments, result
        self.hook_type = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
        api(self.user, "GetForegroundWindow", [], wintypes.HWND)
        api(self.user, "GetWindowThreadProcessId", [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)], wintypes.DWORD)
        api(self.kernel, "OpenProcess", [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE)
        api(self.kernel, "CloseHandle", [wintypes.HANDLE], wintypes.BOOL)
        api(self.kernel, "QueryFullProcessImageNameW", [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                       ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
        api(self.kernel, "GetTickCount", [], wintypes.DWORD)
        api(self.kernel, "GetCurrentThreadId", [], wintypes.DWORD)
        api(self.kernel, "GetModuleHandleW", [wintypes.LPCWSTR], wintypes.HANDLE)
        api(self.kernel, "CreateMutexW", [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE)
        api(self.user, "SetWindowsHookExW", [ctypes.c_int, self.hook_type, wintypes.HANDLE, wintypes.DWORD], wintypes.HANDLE)
        api(self.user, "CallNextHookEx", [wintypes.HANDLE, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM], ctypes.c_ssize_t)
        api(self.user, "UnhookWindowsHookEx", [wintypes.HANDLE], wintypes.BOOL)
        api(self.user, "GetMessageW", [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT], ctypes.c_int)
        api(self.user, "PeekMessageW", [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT, wintypes.UINT], wintypes.BOOL)
        api(self.user, "PostThreadMessageW", [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM], wintypes.BOOL)
        api(self.kernel, "GetLogicalDrives", [], wintypes.DWORD)
        api(self.kernel, "GetDriveTypeW", [wintypes.LPCWSTR], wintypes.UINT)
        api(self.kernel, "CreateFileW", [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE)
        api(self.kernel, "DeviceIoControl", [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                            wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                            wintypes.LPVOID], wintypes.BOOL)

        class LastInput(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]
        self.last_input_type = LastInput
        api(self.user, "GetLastInputInfo", [ctypes.POINTER(LastInput)], wintypes.BOOL)

    def foreground_pid(self):
        pid = wintypes.DWORD()
        window = self.user.GetForegroundWindow()
        if window:
            self.user.GetWindowThreadProcessId(window, ctypes.byref(pid))
        return pid.value

    def process_name(self, pid):
        if not pid or pid == os.getpid():
            return None
        cached = self.process_cache.get(pid)
        if cached and time.monotonic() - cached[1] < 10:
            return cached[0]
        name = "unknown.exe"
        process = self.kernel.OpenProcess(0x1000, False, pid)
        if process:
            try:
                buffer = ctypes.create_unicode_buffer(32768)
                length = wintypes.DWORD(len(buffer))
                if self.kernel.QueryFullProcessImageNameW(process, 0, buffer, ctypes.byref(length)):
                    name = Path(buffer.value).name.lower()
            finally:
                self.kernel.CloseHandle(process)
        if len(self.process_cache) > 1024:
            self.process_cache.clear()
        self.process_cache[pid] = (name, time.monotonic())
        return name

    def _input_callback(self, category, code, message, unused_data):
        # 不解引用键盘/鼠标结构：仅统计事件类别，不读取具体按键、坐标或内容。
        if code == 0:
            kind = None
            if category == "keyboard" and message in (0x100, 0x104):
                kind = "keyboard_events"
            elif category == "mouse" and message in (0x201, 0x204, 0x207, 0x20B):
                kind = "mouse_clicks"
            elif category == "mouse" and message in (0x20A, 0x20E):
                kind = "wheel_events"
            if kind:
                try:
                    pid = self.foreground_pid()
                    if pid and pid != os.getpid():
                        self.events.put_nowait((pid, kind))
                except queue.Full:
                    self.dropped_events += 1
                except Exception:
                    self.dropped_events += 1
        return self.user.CallNextHookEx(None, code, message, unused_data)

    def _hook_loop(self):
        hooks = []
        try:
            self.thread_id = self.kernel.GetCurrentThreadId()
            message = wintypes.MSG()
            self.user.PeekMessageW(ctypes.byref(message), None, 0, 0, 0)
            self.callbacks = (
                self.hook_type(lambda code, msg, data: self._input_callback("keyboard", code, msg, data)),
                self.hook_type(lambda code, msg, data: self._input_callback("mouse", code, msg, data)),
            )
            for kind, callback in zip((13, 14), self.callbacks):
                hook = self.user.SetWindowsHookExW(kind, callback, self.kernel.GetModuleHandleW(None), 0)
                if not hook:
                    raise ctypes.WinError(ctypes.get_last_error())
                hooks.append(hook)
            self.ready.set()
            while True:
                result = self.user.GetMessageW(ctypes.byref(message), None, 0, 0)
                if result == 0:
                    break
                if result == -1:
                    raise ctypes.WinError(ctypes.get_last_error())
        except Exception as exc:
            self.error = exc
            self.ready.set()
        finally:
            for hook in hooks:
                self.user.UnhookWindowsHookEx(hook)

    def start(self):
        self.mutex = self.kernel.CreateMutexW(None, False, f"Local\\LANArchiveMonitor_{self.account}")
        if not self.mutex:
            raise MonitorError("无法创建监控会话。")
        if ctypes.get_last_error() == 183:
            self.kernel.CloseHandle(self.mutex)
            self.mutex = None
            raise MonitorError("该学号的监控已在运行，请使用已有监控窗口。")
        self.ready.clear()
        self.error = None
        self.thread_id = 0
        self.events = queue.Queue(maxsize=10000)
        self.dropped_events = 0
        self.thread = threading.Thread(target=self._hook_loop, name="input-count-hooks", daemon=True)
        self.thread.start()
        if not self.ready.wait(5) or self.error:
            self.stop()
            raise MonitorError("无法启动输入次数统计，请检查 Windows 当前桌面和程序权限。")

    def usb_drives(self):
        mask = self.kernel.GetLogicalDrives()
        present = {f"{chr(65 + bit)}:\\" for bit in range(26) if mask & (1 << bit)}
        self.drive_cache = {drive: value for drive, value in self.drive_cache.items() if drive in present}
        for drive in present - self.drive_cache.keys():
            drive_type = self.kernel.GetDriveTypeW(drive)
            is_external = drive_type == 2  # 权限不足时仍识别可移动盘。
            if drive_type in (2, 3):
                device = self.kernel.CreateFileW("\\\\.\\" + drive[:2], 0, 3, None, 3, 0, None)
                if device and device != ctypes.c_void_p(-1).value:
                    try:
                        query_data = ctypes.create_string_buffer(struct.pack("<III", 0, 0, 0))
                        descriptor, returned = ctypes.create_string_buffer(1024), wintypes.DWORD()
                        if self.kernel.DeviceIoControl(device, 0x002D1400, query_data, 12, descriptor,
                                                       len(descriptor), ctypes.byref(returned), None) and returned.value >= 32:
                            is_external = struct.unpack_from("<I", descriptor.raw, 28)[0] == 7
                    finally:
                        self.kernel.CloseHandle(device)
            self.drive_cache[drive] = is_external
        return {drive for drive, external in self.drive_cache.items() if external}

    def sample(self):
        if self.error:
            raise MonitorError("输入次数统计已停止，请重新启动监控。")
        info = self.last_input_type()
        info.cbSize = ctypes.sizeof(info)
        if not self.user.GetLastInputInfo(ctypes.byref(info)):
            raise MonitorError("无法读取当前会话的操作空闲状态。")
        idle_seconds = ((self.kernel.GetTickCount() - info.dwTime) & 0xFFFFFFFF) / 1000
        return self.process_name(self.foreground_pid()), idle_seconds, self.usb_drives()

    def operations(self):
        for _ in range(10000):
            try:
                pid, kind = self.events.get_nowait()
            except queue.Empty:
                break
            yield self.process_name(pid), kind

    def stop(self):
        if self.thread is not None:
            if self.thread.is_alive() and self.thread_id:
                self.user.PostThreadMessageW(self.thread_id, 0x12, 0, 0)
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise MonitorError("监控线程尚未退出，请关闭本监控窗口后重新启动。")
        if self.mutex:
            self.kernel.CloseHandle(self.mutex)
            self.mutex = None


class VisibleWarning:
    """立即打印提醒，并显示有标题的 Windows 提示框，最多同时显示四个。"""

    def __init__(self):
        self.slots = threading.BoundedSemaphore(4)

    def __call__(self, message):
        print(f"[课堂监控提醒] {message}", flush=True)
        if os.name != "nt" or not self.slots.acquire(blocking=False):
            return

        def popup():
            try:
                user = ctypes.WinDLL("user32", use_last_error=True)
                user.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
                user.MessageBoxW.restype = ctypes.c_int
                user.MessageBoxW(None, message, "课堂监控已启用 — 使用提醒", 0x40000 | 0x30)
            finally:
                self.slots.release()
        threading.Thread(target=popup, name="visible-monitor-warning", daemon=True).start()


class ActivityMonitor:
    def __init__(self, account, *, log_dir=None, apps=None, browsers=None, interval=0.5,
                 idle_threshold=60, warning=None, backend=None, login_at=None, receiver_ip=None):
        if not 0.2 <= interval <= 5 or not 1 <= idle_threshold <= 3600:
            raise MonitorError("采样间隔须为 0.2–5 秒，空闲阈值须为 1–3600 秒。")
        for name in list(apps or []) + list(browsers or []):
            check_process(name)
        self.path = default_status_path(account, log_dir)
        self.session = UsageSession(account, interval, idle_threshold, apps, browsers, warning or VisibleWarning())
        if login_at is not None:
            _date(login_at)
        self.login_at, self.receiver_ip = login_at, receiver_ip
        self.history = None
        self.backend = backend or WindowsBackend(account)
        self.stop_event = threading.Event()
        self.thread = None
        self.error = None
        self.started = False
        self.save_lock = threading.Lock()

    def save(self):
        # GUI 提交快照与定期保存可能同时发生，序列化快照和落盘，避免旧快照晚写覆盖。
        with self.save_lock:
            if self.history is None:
                raise MonitorError("请先启动监控，再保存日志。")
            current = json.loads(self.session.encode(self.backend.dropped_events))
            data = json.dumps(dict(schema=HISTORY_SCHEMA, student_account=self.session.account,
                                   sessions=[*self.history, current]),
                              ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            validate_status_bytes(data, self.session.account)
            atomic_hidden_write(self.path, data)

    def _load_history(self):
        if not self.path.exists():
            return []
        # 损坏或学号不匹配时拒绝覆盖，保留原文件供排查。
        previous = json.loads(read_status_file(self.path, self.session.account))
        sessions = previous["sessions"] if previous["schema"] == HISTORY_SCHEMA else [previous]
        # 同一个 ActivityMonitor 对象再次启动时，也保留上次会话并使用新编号。
        return sessions

    def _sample(self):
        for name, kind in self.backend.operations():
            self.session.operation(name, kind)
        self.session.sample(*self.backend.sample())

    def start(self, *, consent=False):
        if consent is not True:
            raise MonitorError("需要先向学生说明采集范围，并取得学生明确同意后启用。")
        if self.started:
            raise MonitorError("监控已经启用。")
        try:
            self.backend.start()
            self.history = self._load_history()
            device, ip = collect_device_info(self.receiver_ip)
            previous = self.session
            self.session = UsageSession(previous.account, previous.interval, previous.idle_threshold,
                                        previous.allowed, previous.browsers, previous.warning,
                                        login_at=self.login_at, device=device, ip=ip)
            self.stop_event.clear()
            self.error = None
            self._sample()
            self.save()
            self.thread = threading.Thread(target=self._run, name="software-usage-monitor", daemon=True)
            self.started = True
            self.thread.start()
        except Exception:
            self.backend.stop()
            raise

    def _run(self):
        last_save = time.monotonic()
        try:
            while not self.stop_event.wait(self.session.interval):
                self._sample()
                if time.monotonic() - last_save >= 2:
                    self.save()
                    last_save = time.monotonic()
        except Exception as exc:
            self.error = exc
            self.session.state, self.session.error = "error", "监控采集或日志保存失败。"
            self.stop_event.set()

    def stop(self):
        if not self.started:
            return
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=10)
            if self.thread.is_alive():
                raise MonitorError("监控采集线程尚未退出，请关闭程序。")
        self.backend.stop()
        if not self.error:
            self._sample()
            self.session.state = "stopped"
        self.save()
        self.started = False


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--student-account", required=True, help="学生学号")
    parser.add_argument("--log-dir", help="日志目录，默认项目下的 student_status")
    parser.add_argument("--ip", help="教师电脑 IPv4，用于确定学生电脑连接教师端的本机 IP")
    parser.add_argument("--apps", nargs="+", help="统计的软件进程名，例如 code.exe pycharm64.exe；默认全部前台软件")
    parser.add_argument("--browser", action="append", help="补充需要告警的浏览器进程名")
    parser.add_argument("--agree", action="store_true", help="学生已知悉并同意上述统计范围")
    args = parser.parse_args()
    print(NOTICE, flush=True)
    if not args.agree and input("知悉并同意后输入“同意”开始监控：").strip() != "同意":
        print("未启用监控。")
        return 0
    monitor = None
    try:
        monitor = ActivityMonitor(args.student_account, log_dir=args.log_dir, apps=args.apps,
                                  browsers=args.browser, receiver_ip=args.ip)
        monitor.start(consent=True)
        print(f"监控已启用。学号：{args.student_account}\n重点告警：前台浏览器使用、USB 存储设备连接。\n按 Ctrl+C 停止监控。", flush=True)
        while not monitor.stop_event.wait(5):
            status = monitor.session.snapshot(monitor.backend.dropped_events)
            print(f"[监控运行中] 前台：{status['current_process'] or '无'} | 时长 {status['duration_seconds']:.1f}s "
                  f"| 软件 {len(status['applications'])} | 浏览器告警 {len(status['browser_events'])} "
                  f"| USB 告警 {len(status['usb_events'])}", flush=True)
        if monitor.error:
            raise MonitorError("监控已停止：采集或保存失败，请检查目录权限后重新启动。")
    except KeyboardInterrupt:
        print("正在停止监控并保存最终日志…", flush=True)
    except (MonitorError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if monitor is not None:
            monitor.stop()
    print("监控已停止，日志已保存。提交作业时会自动附带该学号的日志。", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
