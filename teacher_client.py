"""教师端 GUI：接收课堂作业、创建/导入学生账号、重置密码。"""

import argparse
from datetime import datetime
from pathlib import Path
import sys
import sqlite3
import threading

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QFileDialog, QFrame, QHBoxLayout, QHeaderView, QLayout,
    QLineEdit, QListWidget, QMainWindow, QMessageBox, QPushButton,
    QScrollArea, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from accounts import DEFAULT_DB, DEFAULT_PASSWORD, AccountDatabase
from student_client import STYLE, TaskThread, card, label
from upload import PORT, Progress, ReceiverServer, TransferError, format_size, local_ipv4_addresses


BASE_DIR = Path(__file__).resolve().parent


class ReceiverBridge(QObject):
    progress = Signal(object)


class TeacherWindow(QMainWindow):
    def __init__(self, *, accounts_db=DEFAULT_DB, save_dir=BASE_DIR / "接收作业",
                 server_factory=ReceiverServer):
        super().__init__()
        self.database = AccountDatabase(accounts_db)
        self.server_factory = server_factory
        self.server = self.server_thread = self.job = None
        self.result = self.error = None
        self.closing = False
        self.bridge = ReceiverBridge(self)
        self.bridge.progress.connect(self._receive_progress)
        self.setWindowTitle("课堂作业 · 教师端")
        self.resize(1080, 980)
        self.setMinimumSize(880, 720)
        self.setStyleSheet(STYLE)
        self._build_ui(str(save_dir))
        self.refresh_accounts()
        self._update_controls()

    def _build_ui(self, save_dir):
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(16)
        layout.addWidget(label("课堂作业 · 教师端", "title"))
        layout.addWidget(label("管理学生账号，开启接收后学生即可登录并提交作业。", "muted"))

        frame, body = card()
        connection = QHBoxLayout()
        self.ip_label = label("教师 IP：" + (" / ".join(local_ipv4_addresses()) or "未检测到，请通过 ipconfig 查看"))
        connection.addWidget(self.ip_label, 1)
        self.service_status = label("● 未开启接收", "muted", wrap=False)
        connection.addWidget(self.service_status)
        body.addLayout(connection)
        row = QHBoxLayout()
        row.addWidget(label("作业保存位置", wrap=False))
        self.save_input = QLineEdit(save_dir)
        row.addWidget(self.save_input, 1)
        self.choose_dir_button = QPushButton("选择目录…")
        self.choose_dir_button.clicked.connect(self._choose_directory)
        row.addWidget(self.choose_dir_button)
        self.start_button = QPushButton("开始接收")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self._start_receiver)
        row.addWidget(self.start_button)
        self.stop_button = QPushButton("停止接收")
        self.stop_button.clicked.connect(self._stop_receiver)
        row.addWidget(self.stop_button)
        body.addLayout(row)
        body.addWidget(label(f"接收端口 {PORT} · 学生填写上方教师 IP · 保持本窗口运行", "muted"))
        layout.addWidget(frame)

        frame, body = card()
        row = QHBoxLayout()
        row.addWidget(label("创建与导入学生账号", "heading"), 1)
        row.addWidget(label(f"初始密码：{DEFAULT_PASSWORD}", "badge", wrap=False))
        body.addLayout(row)
        row = QHBoxLayout()
        self.account_input = QLineEdit()
        self.account_input.setMaxLength(32)
        self.account_input.setPlaceholderText("学号，例如 20260001")
        self.account_input.setMinimumHeight(40)
        row.addWidget(self.account_input, 1)
        self.name_input = QLineEdit()
        self.name_input.setMaxLength(80)
        self.name_input.setPlaceholderText("姓名（可选）")
        self.name_input.setMinimumHeight(40)
        row.addWidget(self.name_input, 1)
        self.create_button = QPushButton("创建账号")
        self.create_button.setObjectName("primary")
        self.create_button.clicked.connect(self._create_account)
        row.addWidget(self.create_button)
        body.addLayout(row)
        row = QHBoxLayout()
        self.import_button = QPushButton("导入 CSV…")
        self.import_button.clicked.connect(self._choose_csv)
        row.addWidget(self.import_button)
        self.template_button = QPushButton("保存 CSV 模板…")
        self.template_button.clicked.connect(self._save_template)
        row.addWidget(self.template_button)
        row.addWidget(label("CSV：学号、姓名（可选）· UTF-8 编码 · 已有学号跳过，密码不变", "muted"), 1)
        body.addLayout(row)
        layout.addWidget(frame)

        frame, body = card()
        row = QHBoxLayout()
        self.count_label = label("学生账号", "heading")
        row.addWidget(self.count_label, 1)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索学号或姓名")
        self.search_input.setMaximumWidth(300)
        self.search_input.textChanged.connect(self._filter_accounts)
        row.addWidget(self.search_input)
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.clicked.connect(self.refresh_accounts)
        row.addWidget(self.refresh_button)
        body.addLayout(row)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["学号", "姓名"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(140)
        self.table.setStyleSheet("QTableWidget { background: white; border: 1px solid #e1e8f1; gridline-color: #edf2f9; } QHeaderView::section { background: #edf2f9; padding: 9px; border: none; }")
        self.table.itemSelectionChanged.connect(self._update_controls)
        body.addWidget(self.table, 1)
        self.reset_button = QPushButton(f"重置选中账号密码为 {DEFAULT_PASSWORD}")
        self.reset_button.clicked.connect(self._reset_password)
        row = QHBoxLayout()
        row.addWidget(self.reset_button)
        row.addWidget(label("学生忘记密码时，选中对应账号再重置。", "muted"), 1)
        body.addLayout(row)
        layout.addWidget(frame, 1)

        frame, body = card()
        body.addWidget(label("操作与接收记录", "heading"))
        self.message = label("就绪：创建学生账号后，点击“开始接收”。", "muted")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        body.addWidget(self.message)
        self.events = QListWidget()
        self.events.setMaximumHeight(80)
        body.addWidget(self.events)
        layout.addWidget(frame)
        for frame in page.findChildren(QFrame):
            if frame.objectName() == "card":
                frame.layout().setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        self.setCentralWidget(scroll)

    def _record(self, message):
        self.message.setText(message)
        self.events.addItem(f"{datetime.now():%H:%M:%S}  {message}")
        self.events.scrollToBottom()

    @Slot()
    def refresh_accounts(self):
        students = self.database.list_students()
        self.table.setRowCount(len(students))
        for index, student in enumerate(students):
            self.table.setItem(index, 0, QTableWidgetItem(student["student_account"]))
            self.table.setItem(index, 1, QTableWidgetItem(student["name"]))
        self.count_label.setText(f"学生账号 · {len(students)} 人")
        self._filter_accounts()
        self._update_controls()

    @Slot()
    def _filter_accounts(self):
        query = self.search_input.text().strip().casefold()
        for row in range(self.table.rowCount()):
            text = " ".join(self.table.item(row, column).text() for column in (0, 1))
            self.table.setRowHidden(row, query not in text.casefold())
        self._update_controls()

    def selected_account(self):
        rows = self.table.selectionModel().selectedRows()
        if rows and not self.table.isRowHidden(rows[0].row()):
            return self.table.item(rows[0].row(), 0).text()
        return None

    @Slot()
    def _update_controls(self):
        busy = self.job is not None or self.closing
        for widget in (self.account_input, self.name_input, self.create_button,
                       self.import_button, self.template_button, self.refresh_button):
            widget.setEnabled(not busy)
        self.reset_button.setEnabled(not busy and self.selected_account() is not None)
        self.start_button.setEnabled(not busy and self.server is None)
        self.stop_button.setEnabled(not busy and self.server is not None)
        self.save_input.setEnabled(not busy and self.server is None)
        self.choose_dir_button.setEnabled(not busy and self.server is None)

    def _launch(self, name, action):
        self.result = self.error = None
        self.job = TaskThread(name, lambda progress: action(), self)
        self.job.succeeded.connect(self._task_succeeded)
        self.job.failed.connect(self._task_failed)
        self.job.finished.connect(self._task_finished)
        self._update_controls()
        self.job.start()

    @Slot(str, object)
    def _task_succeeded(self, name, result):
        self.result = result

    @Slot(str, str)
    def _task_failed(self, name, message):
        self.error = message

    @Slot()
    def _task_finished(self):
        name = self.job.name
        self.job.deleteLater()
        self.job = None
        if self.error:
            self._record(self.error)
            if not self.closing:
                QMessageBox.warning(self, "操作失败", self.error)
        elif name == "create":
            self.account_input.clear()
            self.name_input.clear()
            self.refresh_accounts()
            self._record(f"账号 {self.result} 创建成功，初始密码 {DEFAULT_PASSWORD}。")
        elif name == "import":
            self.refresh_accounts()
            self._record(f"CSV 导入完成：新增 {self.result['imported']} 人，跳过 {self.result['skipped']} 个重复学号。初始密码 {DEFAULT_PASSWORD}。")
        elif name == "reset":
            self._record(f"账号 {self.result} 的密码已重置为 {DEFAULT_PASSWORD}。")
        elif name == "start":
            self.server, self.server_thread = self.result
            self.service_status.setText("● 正在接收")
            self._record("接收服务已启动，学生可以登录并提交作业。")
        elif name == "stop":
            self.server = self.server_thread = None
            self.service_status.setText("● 已停止接收")
            self._record("接收服务已停止。")
        self._update_controls()
        if self.closing:
            if self.server is not None:
                self._stop_receiver()
            else:
                self.close()

    @Slot()
    def _create_account(self):
        if not self.create_button.isEnabled():
            return
        account, name = self.account_input.text().strip(), self.name_input.text().strip()
        def create():
            self.database.add_student(account, name=name)
            return account
        self._launch("create", create)

    @Slot()
    def _choose_csv(self):
        filename, _ = QFileDialog.getOpenFileName(self, "导入学生账号", str(BASE_DIR), "CSV 文件 (*.csv)")
        if filename:
            self.import_accounts(filename)

    def import_accounts(self, path):
        if self.job is not None or self.closing:
            return
        self._record("正在导入 CSV，请稍候…")
        self._launch("import", lambda: self.database.import_csv(path))

    @Slot()
    def _save_template(self):
        filename, _ = QFileDialog.getSaveFileName(self, "保存 CSV 模板", str(BASE_DIR / "学生账号导入模板.csv"), "CSV 文件 (*.csv)")
        if filename:
            try:
                Path(filename).write_text("学号,姓名\n20260001,张三\n20260002,李四\n", encoding="utf-8-sig")
                self._record("模板已保存，请填写学生名单后导入。")
            except OSError as exc:
                QMessageBox.warning(self, "保存失败", str(exc))

    @Slot()
    def _reset_password(self):
        account = self.selected_account()
        if account is None or not self.reset_button.isEnabled():
            return
        def reset():
            self.database.reset_password(account)
            return account
        self._launch("reset", reset)

    @Slot()
    def _choose_directory(self):
        path = QFileDialog.getExistingDirectory(self, "选择作业保存目录", self.save_input.text())
        if path:
            self.save_input.setText(path)

    def _receiver_event(self, event: Progress):
        if event.phase in ("done", "failed", "status"):
            self.bridge.progress.emit(event)

    @Slot(object)
    def _receive_progress(self, event):
        self._record(f"{event.student_account} · {event.filename} · {event.status}" +
                     (f" · {format_size(event.total)}" if event.phase == "done" else ""))

    @Slot()
    def _start_receiver(self):
        if not self.start_button.isEnabled():
            return
        save_dir = self.save_input.text().strip()
        if not save_dir:
            QMessageBox.warning(self, "保存目录", "请选择作业保存目录。")
            return
        def start():
            try:
                server = self.server_factory(save_dir, accounts_db=self.database.path, progress=self._receiver_event)
            except OSError as exc:
                raise TransferError(f"无法启动接收，请检查保存目录或端口 {PORT} 是否已被占用。") from exc
            thread = threading.Thread(target=server.serve_forever, name="teacher-receiver", daemon=True)
            thread.start()
            server.serving.wait()
            return server, thread
        self._record("正在启动接收服务…")
        self._launch("start", start)

    @Slot()
    def _stop_receiver(self):
        if self.server is None or self.job is not None:
            return
        server, thread = self.server, self.server_thread
        def stop():
            server.close()
            thread.join()
        self._record("正在停止接收服务…")
        self._launch("stop", stop)

    def closeEvent(self, event):
        if self.server is None and self.job is None:
            event.accept()
            return
        event.ignore()
        self.closing = True
        self._update_controls()
        if self.job is None:
            self._stop_receiver()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accounts-db", default=str(DEFAULT_DB))
    parser.add_argument("--save-dir", default=str(BASE_DIR / "接收作业"))
    args = parser.parse_args()
    app = QApplication(sys.argv[:1])
    app.setFont(QFont("Microsoft YaHei UI", 10))
    try:
        window = TeacherWindow(accounts_db=args.accounts_db, save_dir=args.save_dir)
    except (ValueError, OSError, sqlite3.Error) as exc:
        QMessageBox.warning(None, "教师端启动失败", str(exc))
        return 1
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
