"""学生端：填写信息 → 确认监控 → 选择压缩文件并上传。

教师端验证账号密码后才能进入；上传和监控日志使用短期登录令牌。
运行：python student_client.py [--ip 192.168.1.20]
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import sys
import threading
from typing import Callable

try:
    from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot
    from PySide6.QtGui import QCloseEvent, QFont
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame, QHBoxLayout, QLabel,
        QLineEdit, QListWidget, QMainWindow, QMessageBox, QProgressBar,
        QPushButton, QScrollArea, QStackedWidget, QVBoxLayout, QWidget,
    )
except ImportError:
    raise SystemExit("缺少 PySide6，请先执行：python -m pip install -r requirements.txt")

from monitoring import ActivityMonitor, NOTICE, utc_now
from upload import (
    PORT, Progress, TransferError, UploadCancelled, change_student_password, format_size, login_student, logout_student,
    upload_file, validate_ip, validate_open_file, validate_student_account,
)


BASE_DIR = Path(__file__).resolve().parent
MONITOR_NOTICE = NOTICE + "\n不记录具体按键内容、窗口标题、网址、网页正文或 U 盘文件。"


@dataclass(frozen=True)
class StudentSession:
    account: str
    receiver_ip: str
    login_at: str = field(default_factory=utc_now)
    token: str = field(default="", repr=False)
    expires_at: str = ""


def enter_student_session(receiver_ip: str, account: str, password: str, *, port: int = PORT) -> StudentSession:
    """只在教师端验证成功后建立学生会话，不保存明文密码。"""
    ip = validate_ip(receiver_ip)
    account = validate_student_account(account)
    if not password or not password.strip():
        raise TransferError("请填写密码。")
    result = login_student(ip, account, password, port=port, require_status=True)
    return StudentSession(account, ip, token=result["token"], expires_at=result["expires_at"])


class TaskThread(QThread):
    """耗时任务在 run 中执行；窗口只在主线程接收信号。"""

    succeeded = Signal(str, object)
    failed = Signal(str, str)
    progress = Signal(object)

    def __init__(self, name: str, action: Callable, parent: QObject):
        super().__init__(parent)
        self.name, self.action = name, action

    def run(self):
        try:
            self.succeeded.emit(self.name, self.action(self.progress.emit))
        except UploadCancelled:
            self.failed.emit(self.name, "上传已取消；若文件已被教师端确认保存，取消不会撤回该作业。")
        except Exception as exc:
            message = str(exc) if isinstance(exc, (TransferError, ValueError, OSError)) else "操作失败，请重试或联系教师。"
            self.failed.emit(self.name, message)
        finally:
            # 不在已完成的任务中继续保留登录密码等闭包数据。
            self.action = None


class WarningBridge(QObject):
    warning = Signal(str)


STYLE = """
QWidget { font-family: 'Microsoft YaHei UI', 'Microsoft YaHei'; font-size: 14px; color: #25364c; }
QMainWindow, QWidget#page { background: #f3f6fb; }
QFrame#card { background: white; border: 1px solid #dce5f0; border-radius: 14px; }
QLabel#title { font-size: 26px; font-weight: 700; color: #142d51; }
QLabel#heading { font-size: 18px; font-weight: 700; }
QLabel#muted { color: #63758c; }
QLabel#notice { background: #fff6df; color: #86601e; border-radius: 7px; padding: 10px; }
QLabel#error { color: #b43b32; }
QLabel#badge { background: #e8f0fe; color: #275ca5; border-radius: 7px; padding: 8px; }
QLineEdit { border: 1px solid #cbd8e8; border-radius: 7px; padding: 10px; background: #fff; }
QLineEdit:focus { border: 1px solid #3778d6; }
QLineEdit:disabled { background: #f2f5f9; color: #7c8ba0; }
QPushButton { background: #edf2f9; border: 1px solid #d6e0ed; border-radius: 7px; padding: 10px 17px; }
QPushButton:hover { background: #e1eaf7; }
QPushButton#primary { color: white; background: #2868c6; border: 1px solid #2868c6; font-weight: 600; }
QPushButton#primary:hover { background: #2059ac; }
QPushButton:disabled, QPushButton#primary:disabled { background: #edf1f6; color: #8b97a9; border-color: #e1e7ef; }
QCheckBox { spacing: 8px; padding: 4px 0; }
QCheckBox::indicator { width: 18px; height: 18px; }
QProgressBar { border: 1px solid #dce5f0; border-radius: 6px; background: #edf2f9; min-height: 20px; text-align: center; }
QProgressBar::chunk { background: #4282de; border-radius: 5px; }
QListWidget { border: 1px solid #e1e8f1; border-radius: 7px; background: #fafcff; padding: 5px; }
QListWidget::item { padding: 4px; }
QScrollArea { border: none; background: #f3f6fb; }
"""


def label(text: str, name: str = "", *, wrap: bool = True) -> QLabel:
    result = QLabel(text)
    result.setObjectName(name)
    result.setWordWrap(wrap)
    return result


def card() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(22, 18, 22, 18)
    layout.setSpacing(12)
    return frame, layout


class StudentWindow(QMainWindow):
    def __init__(self, receiver_ip: str = "", *, monitor_factory=ActivityMonitor,
                 uploader=upload_file, session_opener=enter_student_session, session_closer=logout_student,
                 password_changer=change_student_password):
        super().__init__()
        self.setWindowTitle("课堂作业 · 学生端")
        self.resize(920, 820)
        self.setMinimumSize(600, 620)
        self.setStyleSheet(STYLE)
        self.monitor_factory, self.uploader, self.session_opener = monitor_factory, uploader, session_opener
        self.session_closer = session_closer
        self.password_changer = password_changer
        self.session: StudentSession | None = None
        self.monitor: ActivityMonitor | None = None
        self.selected_file: Path | None = None
        self.cancel_upload = threading.Event()
        self.jobs: dict[str, TaskThread] = {}
        self.results: dict[str, object] = {}
        self.errors: dict[str, str] = {}
        self.exit_destination: str | None = None
        self.monitor_fault_shown = False
        self.warning_bridge = WarningBridge(self)
        self.warning_bridge.warning.connect(self._on_warning)
        self.pages = QStackedWidget()
        self.setCentralWidget(self.pages)
        self._build_login(receiver_ip)
        self._build_workspace()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_monitor)
        self.timer.start(1000)
        self._update_controls()

    def _build_login(self, receiver_ip: str):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(30, 24, 30, 24)
        outer.addStretch()
        frame, body = card()
        frame.setFixedWidth(480)
        body.addWidget(label("课堂作业", "title"))
        body.addWidget(label("学生端 · 登录后确认监控，再提交作业", "muted"))
        body.addSpacing(10)
        body.addWidget(label("教师电脑 IP"))
        self.ip_input = QLineEdit(receiver_ip)
        self.ip_input.setPlaceholderText("例如 192.168.1.20")
        self.ip_input.setMaxLength(15)
        body.addWidget(self.ip_input)
        body.addWidget(label("学号"))
        self.account_input = QLineEdit()
        self.account_input.setMaxLength(32)
        self.account_input.setPlaceholderText("填写你的学号，保留前导零")
        body.addWidget(self.account_input)
        body.addWidget(label("密码"))
        password_row = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setMaxLength(128)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("填写密码")
        password_row.addWidget(self.password_input, 1)
        self.show_password = QCheckBox("显示")
        self.show_password.toggled.connect(self._toggle_password)
        password_row.addWidget(self.show_password)
        body.addLayout(password_row)
        password_notice = label("账号由教师创建。学号和密码验证通过后才能进入；忘记密码请联系教师。", "notice")
        password_notice.setMinimumHeight(64)
        body.addWidget(password_notice)
        self.login_message = label("", "error")
        body.addWidget(self.login_message)
        self.login_button = QPushButton("进入学生端")
        self.login_button.setObjectName("primary")
        self.login_button.clicked.connect(self._login)
        for field in (self.ip_input, self.account_input, self.password_input):
            field.returnPressed.connect(self._login)
        body.addWidget(self.login_button)
        outer.addWidget(frame, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch()
        outer.addWidget(label("与教师电脑连接同一局域网 · 接收端口 9000", "muted", wrap=False), 0, Qt.AlignmentFlag.AlignHCenter)
        self.pages.addWidget(page)

    def _build_workspace(self):
        content = QWidget()
        content.setObjectName("page")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(16)
        header = QHBoxLayout()
        header.addWidget(label("课堂作业 · 学生端", "title"), 1)
        self.change_password_button = QPushButton("修改密码")
        self.change_password_button.clicked.connect(self._change_password)
        header.addWidget(self.change_password_button)
        self.logout_button = QPushButton("退出登录")
        self.logout_button.clicked.connect(self._logout)
        header.addWidget(self.logout_button)
        layout.addLayout(header)
        self.identity_label = label("", "muted")
        self.identity_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.identity_label)
        layout.addWidget(label("① 填写信息    →    ② 确认监控    →    ③ 选择文件并提交", "badge"))

        frame, body = card()
        body.addWidget(label("确认课堂监控", "heading"))
        body.addWidget(label(MONITOR_NOTICE, "muted"))
        self.consent = QCheckBox("我已知悉上述采集范围，同意启用课堂监控")
        self.consent.toggled.connect(self._update_controls)
        body.addWidget(self.consent)
        row = QHBoxLayout()
        self.start_monitor_button = QPushButton("确认并启用监控")
        self.start_monitor_button.setObjectName("primary")
        self.start_monitor_button.clicked.connect(self._start_monitor)
        self.stop_monitor_button = QPushButton("停止监控")
        self.stop_monitor_button.clicked.connect(self._stop_monitor)
        row.addWidget(self.start_monitor_button)
        row.addWidget(self.stop_monitor_button)
        row.addStretch()
        self.monitor_status = label("● 未启用", "muted", wrap=False)
        row.addWidget(self.monitor_status)
        body.addLayout(row)
        self.monitor_details = label("确认后开始采集；关闭程序或退出登录会停止监控并保存日志。", "muted")
        self.monitor_details.setTextFormat(Qt.TextFormat.PlainText)
        body.addWidget(self.monitor_details)
        layout.addWidget(frame)

        frame, body = card()
        body.addWidget(label("提交作业", "heading"))
        body.addWidget(label("选择已压缩好的 ZIP / RAR 文件。提交时会自动附带本次监控日志。", "muted"))
        file_row = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setReadOnly(True)
        self.file_input.setPlaceholderText("启用监控后，点击右侧按钮选择文件")
        self.choose_button = QPushButton("选择文件…")
        self.choose_button.clicked.connect(self._choose_file)
        file_row.addWidget(self.file_input, 1)
        file_row.addWidget(self.choose_button)
        body.addLayout(file_row)
        self.file_details = label("支持 .zip、.rar；同一学号下同名作业会被本次提交覆盖。", "muted")
        self.file_details.setTextFormat(Qt.TextFormat.PlainText)
        body.addWidget(self.file_details)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p%")
        body.addWidget(self.progress_bar)
        self.upload_status = label("请先确认并启用监控。", "muted")
        self.upload_status.setTextFormat(Qt.TextFormat.PlainText)
        body.addWidget(self.upload_status)
        row = QHBoxLayout()
        self.upload_button = QPushButton("上传作业")
        self.upload_button.setObjectName("primary")
        self.upload_button.clicked.connect(self._upload)
        self.cancel_button = QPushButton("取消上传")
        self.cancel_button.clicked.connect(self._cancel_upload)
        row.addWidget(self.upload_button)
        row.addWidget(self.cancel_button)
        row.addStretch()
        body.addLayout(row)
        layout.addWidget(frame)

        frame, body = card()
        body.addWidget(label("课堂提醒与提交记录", "heading"))
        self.events = QListWidget()
        self.events.setMinimumHeight(110)
        self.events.setMaximumHeight(160)
        body.addWidget(self.events)
        layout.addWidget(frame)
        layout.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        self.pages.addWidget(scroll)

    @Slot(bool)
    def _toggle_password(self, visible):
        self.password_input.setEchoMode(QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)

    @Slot()
    def _login(self):
        if self.jobs or self.exit_destination:
            return
        ip, account, password = self.ip_input.text().strip(), self.account_input.text().strip(), self.password_input.text()
        try:
            validate_ip(ip)
            validate_student_account(account)
            if not password.strip():
                raise TransferError("请填写密码。密码验证功能后续接入。")
        except TransferError as exc:
            self.login_message.setText(exc.message)
            return
        opener = self.session_opener
        self.password_input.clear()
        self.show_password.setChecked(False)
        self.login_message.setText("正在连接教师端…")
        self._launch("login", lambda progress: opener(ip, account, password))

    def _launch(self, name, action):
        worker = TaskThread(name, action, self)
        self.jobs[name] = worker
        worker.succeeded.connect(self._task_succeeded)
        worker.failed.connect(self._task_failed)
        worker.progress.connect(self._on_progress)
        worker.finished.connect(self._task_finished)
        self._update_controls()
        worker.start()

    @Slot(str, object)
    def _task_succeeded(self, name, result):
        self.results[name] = result

    @Slot(str, str)
    def _task_failed(self, name, message):
        self.errors[name] = message

    @Slot()
    def _task_finished(self):
        worker = self.sender()
        name = worker.name
        self.jobs.pop(name, None)
        result = self.results.pop(name, None)
        error = self.errors.pop(name, None)
        worker.deleteLater()
        if error:
            if name == "login":
                self.login_message.setText(error)
            elif name == "upload":
                self.progress_bar.setRange(0, 1000)
                self.upload_status.setText(error)
                self._record(error)
            elif name == "logout":
                self._record(error)
                self.session = None
            elif name == "change_password":
                QMessageBox.warning(self, "修改密码失败", error)
            else:
                self.monitor_status.setText("● 监控操作失败")
                self.monitor_details.setText(error)
                self._record(error)
                # 停止失败时保留监控引用，允许学生重试关闭，避免遗留后台采集。
                self.exit_destination = None
                QMessageBox.warning(self, "监控操作失败", error)
        elif name == "login":
            self.session = result
            self.identity_label.setText(f"学号 {result.account}    ·    教师电脑 {result.receiver_ip}:9000")
            self.login_message.clear()
            self.pages.setCurrentIndex(1)
            self._record("已进入学生端，请确认监控范围。")
        elif name == "logout":
            self.session = None
        elif name == "change_password":
            self.login_message.setText("密码修改成功，请使用新密码登录。")
            self._request_exit("login")
        elif name == "start_monitor":
            self.monitor = result
            self.monitor_fault_shown = False
            self.monitor_status.setText("● 监控运行中")
            self.upload_status.setText("监控已启用，请选择作业文件。")
            self._record("已确认并启用课堂监控。")
            self._poll_monitor()
        elif name == "stop_monitor":
            self.monitor = None
            self.consent.setChecked(False)
            self.monitor_status.setText("● 监控已停止")
            self.monitor_details.setText("日志已保存。再次启用监控会追加新会话，已有记录继续保留。")
            self.upload_status.setText("监控已停止；重新启用后可以继续上传作业。")
            self._record("监控已停止，日志已保存。")
        elif name == "upload":
            self.progress_bar.setRange(0, 1000)
            self.progress_bar.setValue(1000)
            self.upload_status.setText(f"作业提交成功：{result['filename']}（教师端已确认文件及监控日志）。")
            self._record(f"提交成功：{result['filename']}")
        self._update_controls()
        if self.exit_destination:
            self._continue_exit()

    def _monitor_running(self):
        return self.monitor is not None and self.monitor.started and self.monitor.error is None

    @Slot()
    def _update_controls(self):
        busy = bool(self.jobs) or self.exit_destination is not None
        login_busy = "login" in self.jobs or self.exit_destination is not None
        for widget in (self.ip_input, self.account_input, self.password_input, self.show_password, self.login_button):
            widget.setEnabled(not login_busy)
        running = self._monitor_running()
        self.consent.setEnabled(self.monitor is None and not busy)
        self.start_monitor_button.setEnabled(self.session is not None and self.monitor is None and self.consent.isChecked() and not busy)
        self.stop_monitor_button.setEnabled(self.monitor is not None and not busy)
        self.choose_button.setEnabled(running and not busy)
        self.upload_button.setEnabled(running and self.selected_file is not None and not busy)
        self.cancel_button.setEnabled("upload" in self.jobs and not self.cancel_upload.is_set() and self.exit_destination is None)
        self.logout_button.setEnabled(self.session is not None and not busy)
        self.change_password_button.setEnabled(self.session is not None and not busy)

    @Slot()
    def _start_monitor(self):
        if not self.start_monitor_button.isEnabled():
            return
        factory, session = self.monitor_factory, self.session
        warning = self.warning_bridge.warning.emit

        def start(progress):
            monitor = factory(session.account, log_dir=BASE_DIR / "student_status", warning=warning,
                              login_at=session.login_at, receiver_ip=session.receiver_ip)
            monitor.start(consent=True)
            return monitor

        self.monitor_status.setText("● 正在启动…")
        self._launch("start_monitor", start)

    @Slot()
    def _stop_monitor(self):
        if self.monitor is None or self.jobs:
            return
        monitor = self.monitor
        self.monitor_status.setText("● 正在停止并保存…")
        self._launch("stop_monitor", lambda progress: monitor.stop())

    @Slot()
    def _poll_monitor(self):
        if (self.session and self.session.expires_at and not self.exit_destination
                and datetime.fromisoformat(self.session.expires_at) <= datetime.now(timezone.utc)):
            self.login_message.setText("登录已过期，请重新输入账号密码。")
            self._request_exit("login")
            return
        if self.monitor is None or "stop_monitor" in self.jobs:
            return
        if self.monitor.error is not None:
            self.monitor_status.setText("● 监控异常")
            self.monitor_details.setText("监控采集或日志保存失败，请停止监控后重新启用。")
            if not self.monitor_fault_shown:
                self.monitor_fault_shown = True
                if "upload" in self.jobs:
                    self.cancel_upload.set()
                self._record("监控发生异常，暂停新的提交；请停止后重新启用。")
            self._update_controls()
            return
        snapshot = self.monitor.session.snapshot(self.monitor.backend.dropped_events)
        seconds = int(snapshot["duration_seconds"])
        self.monitor_details.setText(
            f"本次时长 {seconds // 60:02d}:{seconds % 60:02d}    ·    前台软件 {snapshot['current_process'] or '无'}\n"
            f"软件 {len(snapshot['applications'])} 个    ·    浏览器告警 {len(snapshot['browser_events'])} 次"
            f"    ·    USB 告警 {len(snapshot['usb_events'])} 次"
        )

    @Slot(str)
    def _on_warning(self, message):
        self._record(message)
        if self.exit_destination:
            return
        # 非模态提醒：弹出告警时，进度和关闭流程仍能响应。
        box = QMessageBox(QMessageBox.Icon.Warning, "课堂监控提醒", message, QMessageBox.StandardButton.Ok, self)
        box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        box.open()

    def _record(self, message):
        self.events.addItem(f"{datetime.now().strftime('%H:%M:%S')}  {message}")
        if self.events.count() > 200:
            self.events.takeItem(0)
        self.events.scrollToBottom()

    @Slot()
    def _choose_file(self):
        if not self.choose_button.isEnabled():
            return
        filename, _ = QFileDialog.getOpenFileName(self, "选择已压缩好的作业文件", "", "压缩作业 (*.zip *.rar);;ZIP 文件 (*.zip);;RAR 文件 (*.rar)")
        if filename:
            self.select_file(Path(filename))

    def select_file(self, path: Path) -> bool:
        """只读文件头验证；整文件校验由上传线程完成。"""
        if not self._monitor_running() or self.jobs or self.exit_destination:
            return False
        path = Path(path)
        try:
            with path.open("rb") as stream:
                size, kind = validate_open_file(stream, path.name)
        except (TransferError, OSError) as exc:
            self.selected_file = None
            self.file_input.clear()
            self.file_details.setText("请重新选择有效的 ZIP / RAR 文件。")
            self.upload_status.setText(str(exc))
            self._update_controls()
            return False
        self.selected_file = path
        self.file_input.setText(str(path))
        self.file_details.setText(f"{path.name}    ·    {kind}    ·    {format_size(size)}")
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(0)
        self.upload_status.setText("文件已选择，点击“上传作业”提交。")
        self._update_controls()
        return True

    @Slot()
    def _upload(self):
        if not self.upload_button.isEnabled():
            return
        uploader, path, session, monitor = self.uploader, self.selected_file, self.session, self.monitor
        self.cancel_upload = threading.Event()
        cancel = self.cancel_upload

        def send(progress):
            # 快照在提交前从当前会话生成，不复用其他学号或旧会话的日志。
            if monitor.error is not None or not monitor.started:
                raise TransferError("监控已停止或异常，请重新启用后提交。")
            monitor.save()
            return uploader(path, session.account, session.receiver_ip, status_file=monitor.path,
                            progress=progress, cancel=cancel, session_token=session.token)

        self.progress_bar.setValue(0)
        self.upload_status.setText("正在准备上传…")
        self._launch("upload", send)

    @Slot(object)
    def _on_progress(self, event: Progress):
        if event.phase in ("connecting", "retrying", "verifying", "status"):
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, 1000)
            self.progress_bar.setValue(int(event.percentage * 10))
        detail = ""
        if event.phase in ("hashing", "uploading"):
            detail = f" · {format_size(event.done)} / {format_size(event.total)} · {format_size(event.speed)}/s"
        self.upload_status.setText(event.status + detail)

    @Slot()
    def _cancel_upload(self):
        if "upload" in self.jobs:
            self.cancel_upload.set()
            self.upload_status.setText("正在取消，请等待当前网络请求结束…")
            self._update_controls()

    @Slot()
    def _change_password(self):
        if not self.change_password_button.isEnabled():
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("修改密码")
        form = QFormLayout(dialog)
        fields = []
        for title in ("旧密码", "新密码", "确认新密码"):
            field = QLineEdit()
            field.setEchoMode(QLineEdit.EchoMode.Password)
            field.setMaxLength(128)
            form.addRow(title, field)
            fields.append(field)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("保存")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.submit_password_change(*(field.text() for field in fields))
        for field in fields:
            field.clear()
        dialog.deleteLater()

    def submit_password_change(self, old_password: str, new_password: str, confirmation: str) -> bool:
        if self.session is None or self.jobs or self.exit_destination:
            return False
        if not old_password.strip() or not new_password.strip():
            QMessageBox.warning(self, "修改密码", "请填写旧密码和新密码。")
            return False
        if new_password != confirmation:
            QMessageBox.warning(self, "修改密码", "两次新密码不一致。")
            return False
        session, changer = self.session, self.password_changer
        self._launch("change_password", lambda progress:
                     changer(session.receiver_ip, session.token, old_password, new_password))
        return True

    @Slot()
    def _logout(self):
        if self.jobs:
            return
        if self.monitor and QMessageBox.question(self, "退出登录", "退出会停止监控并保存日志。确定退出？") != QMessageBox.StandardButton.Yes:
            return
        self._request_exit("login")

    def _request_exit(self, destination):
        self.exit_destination = destination
        if "upload" in self.jobs:
            self.cancel_upload.set()
            self.upload_status.setText("正在取消上传并结束监控，请稍候…")
        self._update_controls()
        self._continue_exit()

    def _continue_exit(self):
        if self.jobs:
            return
        if self.monitor is not None:
            self._stop_monitor()
            return
        if self.session is not None and self.session.token:
            session, closer = self.session, self.session_closer
            self._launch("logout", lambda progress: closer(session.receiver_ip, session.token))
            return
        destination = self.exit_destination
        self.exit_destination = None
        if destination == "close":
            self.close()
            return
        self.session, self.selected_file = None, None
        self.password_input.clear()
        self.consent.setChecked(False)
        self.file_input.clear()
        self.events.clear()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(0)
        self.monitor_status.setText("● 未启用")
        self.monitor_details.setText("确认后开始采集；关闭程序或退出登录会停止监控并保存日志。")
        self.file_details.setText("支持 .zip、.rar；同一学号下同名作业会被本次提交覆盖。")
        self.upload_status.setText("请先确认并启用监控。")
        self.pages.setCurrentIndex(0)
        self._update_controls()

    def closeEvent(self, event: QCloseEvent):
        if self.exit_destination:
            event.ignore()
            return
        if self.monitor is None and not self.jobs and (self.session is None or not self.session.token):
            event.accept()
            return
        event.ignore()
        message = "关闭会停止监控并保存日志。"
        if "upload" in self.jobs:
            message += "正在上传的任务会取消，已保存的作业不会撤回。"
        if QMessageBox.question(self, "关闭学生端", message + "确定关闭？") == QMessageBox.StandardButton.Yes:
            self._request_exit("close")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default="", help="预填教师电脑 IPv4 地址")
    args = parser.parse_args()
    app = QApplication(sys.argv[:1])
    app.setApplicationName("课堂作业学生端")
    app.setFont(QFont("Microsoft YaHei UI", 10))
    window = StudentWindow(args.ip)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
