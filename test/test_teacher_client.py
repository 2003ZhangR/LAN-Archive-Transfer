"""教师端默认密码、CSV 导入和 GUI 接收服务的回归测试。"""

import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtCore import QPoint
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

from accounts import AccountDatabase, AccountError, main as accounts_main
from teacher_client import TeacherWindow
from upload import ReceiverServer, TransferError, change_student_password, login_student, upload_file


ARTIFACTS = Path(__file__).resolve().parent / "artifacts"


class CSVAccountTests(unittest.TestCase):
    def setUp(self):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ARTIFACTS)
        self.root = Path(self.temporary.name)
        self.database = AccountDatabase(self.root / "students.sqlite3")

    def tearDown(self):
        self.temporary.cleanup()

    def test_creation_defaults_to_12345678_without_prompt(self):
        args = ["accounts.py", "--db", str(self.database.path), "add", "--student-account", "001234", "--name", "张三"]
        with patch("sys.argv", args), patch("getpass.getpass", side_effect=AssertionError("创建无需输入密码")), patch("builtins.print"):
            self.assertEqual(accounts_main(), 0)
        self.assertEqual(self.database.verify_password("001234", "12345678"), 1)
        self.assertEqual(self.database.get_student("001234")["name"], "张三")

    def test_csv_skips_duplicates_and_preserves_changed_password(self):
        self.database.add_student("000001", name="原姓名")
        self.database.change_password("000001", "12345678", "Student-changed")
        path = self.root / "学生.csv"
        path.write_text("学号,姓名\n000001,不同姓名\n000002,李四\n000002,重复姓名\n", encoding="utf-8-sig")
        self.assertEqual(self.database.import_csv(path), {"imported": 1, "skipped": 2})
        self.assertEqual(self.database.verify_password("000001", "Student-changed"), 2)
        self.assertEqual(self.database.get_student("000001")["name"], "原姓名")
        self.assertEqual(self.database.verify_password("000002", "12345678"), 1)
        self.assertEqual(self.database.get_student("000002")["name"], "李四")

    def test_csv_english_header_and_optional_name(self):
        path = self.root / "students.csv"
        path.write_text("student_account\n001234\n", encoding="utf-8")
        self.assertEqual(self.database.import_csv(path), {"imported": 1, "skipped": 0})
        self.assertEqual(self.database.get_student("001234")["name"], "")

    def test_invalid_csv_row_does_not_partially_create_accounts(self):
        path = self.root / "students.csv"
        path.write_text("学号,姓名\n001234,张三\n../invalid,李四\n", encoding="utf-8-sig")
        with self.assertRaisesRegex(AccountError, "第 3 行"):
            self.database.import_csv(path)
        self.assertEqual(self.database.list_students(), [])


class TeacherClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)
        if os.name == "nt":
            for name in ("msyh.ttc", "msyhbd.ttc"):
                QFontDatabase.addApplicationFont(str(Path(os.environ["WINDIR"]) / "Fonts" / name))
        cls.app.setFont(QFont("Microsoft YaHei UI", 10))
        ARTIFACTS.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ARTIFACTS)
        self.root = Path(self.temporary.name)
        self.warnings = patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Ok)
        self.warning = self.warnings.start()
        self.window = TeacherWindow(accounts_db=self.root / "students.sqlite3", save_dir=self.root / "received",
                                    server_factory=lambda *args, **kwargs: ReceiverServer(*args, host="127.0.0.1", port=0, **kwargs))
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        self.window.close()
        self.wait_for(lambda: self.window.job is None and self.window.server is None)
        self.app.processEvents()
        self.warnings.stop()
        self.temporary.cleanup()

    def wait_for(self, condition, timeout=10):
        deadline = time.monotonic() + timeout
        while not condition():
            if time.monotonic() > deadline:
                self.fail("教师端后台操作未完成")
            self.app.processEvents()
            QTest.qWait(10)
        self.app.processEvents()

    def create_account(self, account="001234", name="张三"):
        self.window.account_input.setText(account)
        self.window.name_input.setText(name)
        self.window.create_button.click()
        self.wait_for(lambda: self.window.job is None)

    def test_gui_create_and_search(self):
        self.create_account()
        self.assertEqual(self.window.database.verify_password("001234", "12345678"), 1)
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 1).text(), "张三")
        self.window.search_input.setText("李四")
        self.assertTrue(self.window.table.isRowHidden(0))
        self.window.search_input.setText("001234")
        self.assertFalse(self.window.table.isRowHidden(0))

    def test_csv_picker_import_and_template(self):
        path = self.root / "students.csv"
        path.write_text("学号,姓名\n000001,张三\n000002,李四\n", encoding="utf-8-sig")
        with patch.object(QFileDialog, "getOpenFileName", return_value=(str(path), "")):
            self.window.import_button.click()
        self.wait_for(lambda: self.window.job is None)
        self.assertEqual(self.window.table.rowCount(), 2)
        self.assertIn("新增 2 人", self.window.message.text())
        self.assertEqual(self.window.database.verify_password("000001", "12345678"), 1)
        template = self.root / "template.csv"
        with patch.object(QFileDialog, "getSaveFileName", return_value=(str(template), "")):
            self.window.template_button.click()
        self.assertTrue(template.read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertTrue(template.read_text(encoding="utf-8-sig").startswith("学号,姓名\n"))

    def test_receiver_login_upload_and_gui_password_reset(self):
        self.create_account()
        self.window.start_button.click()
        self.wait_for(lambda: self.window.job is None and self.window.server is not None)
        server, thread = self.window.server, self.window.server_thread
        self.assertFalse(self.window.save_input.isEnabled())
        session = login_student("127.0.0.1", "001234", "12345678", port=server.server_port)
        archive = self.root / "作业.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr("main.py", "print(1)")
        result = upload_file(archive, "001234", "127.0.0.1", port=server.server_port, session_token=session["token"])
        self.assertTrue(result["ok"])
        self.wait_for(lambda: any("接收成功" in self.window.events.item(i).text() for i in range(self.window.events.count())))
        change_student_password("127.0.0.1", session["token"], "12345678", "Student-changed", port=server.server_port)
        changed = login_student("127.0.0.1", "001234", "Student-changed", port=server.server_port)
        self.window.table.selectRow(0)
        self.window.reset_button.click()
        self.wait_for(lambda: self.window.job is None)
        self.assertIn("已重置为 12345678", self.window.message.text())
        with self.assertRaises(TransferError):
            upload_file(archive, "001234", "127.0.0.1", port=server.server_port, session_token=changed["token"])
        self.assertTrue(login_student("127.0.0.1", "001234", "12345678", port=server.server_port)["ok"])
        self.window.close()
        self.wait_for(lambda: self.window.job is None and self.window.server is None)
        self.assertFalse(thread.is_alive())
        self.assertFalse(self.window.isVisible())

    def test_duplicate_account_reports_error_and_keeps_student_password(self):
        self.create_account()
        self.window.database.change_password("001234", "12345678", "Student-changed")
        self.create_account()
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.database.verify_password("001234", "Student-changed"), 2)
        self.assertIn("已存在", self.window.message.text())

    def test_teacher_gui_preview(self):
        self.create_account()
        self.create_account("001235", "李四")
        self.window.table.selectRow(0)
        self.app.processEvents()
        self.assertLessEqual(self.window.table.mapTo(self.window, QPoint(0, self.window.table.height())).y(),
                             self.window.reset_button.mapTo(self.window, QPoint()).y())
        self.assertTrue(self.window.grab().save(str(ARTIFACTS / "教师端-账号管理.png")))
        self.window.resize(880, 720)
        self.app.processEvents()
        self.assertGreaterEqual(self.window.account_input.height(), 40)
        self.assertLessEqual(self.window.table.mapTo(self.window, QPoint(0, self.window.table.height())).y(),
                             self.window.reset_button.mapTo(self.window, QPoint()).y())


if __name__ == "__main__":
    unittest.main()
