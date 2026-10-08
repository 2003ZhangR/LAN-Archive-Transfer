"""学生登录、学生改密、教师重置及上传认证测试。"""

import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

from accounts import AccountDatabase, AccountError, Authenticator, main as accounts_main
from monitoring import UsageSession
from upload import (
    METADATA_HEADER, ReceiverServer, Submission, TransferError, auth_headers,
    change_student_password, login_student, logout_student, upload_file,
)

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
PASSWORD = "Student-2026"


class AccountTests(unittest.TestCase):
    def setUp(self):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ARTIFACTS)
        self.root = Path(self.temporary.name)
        self.database = AccountDatabase(self.root / "students.sqlite3")
        self.database.add_student("001234", PASSWORD, "张三")

    def tearDown(self):
        self.temporary.cleanup()

    def test_password_hash_and_persistent_login(self):
        self.assertNotIn(PASSWORD.encode(), self.database.path.read_bytes())
        self.assertNotIn("password", json.dumps(self.database.list_students()))
        self.assertEqual(AccountDatabase(self.database.path).verify_password("001234", PASSWORD), 1)
        with self.assertRaises(AccountError):
            self.database.verify_password("001234", "wrong")
        with self.assertRaises(AccountError):
            self.database.verify_password("1234", PASSWORD)

    def test_duplicate_account_does_not_overwrite_password(self):
        with self.assertRaises(AccountError):
            self.database.add_student("001234", "another")
        self.assertEqual(self.database.verify_password("001234", PASSWORD), 1)

    def test_wrong_old_password_preserves_current_password(self):
        with self.assertRaises(AccountError):
            self.database.change_password("001234", "wrong", "New-password")
        self.assertEqual(self.database.verify_password("001234", PASSWORD), 1)

    def test_change_and_reset_invalidate_old_sessions(self):
        auth = Authenticator(self.database)
        token = auth.login("001234", PASSWORD)["token"]
        self.database.change_password("001234", PASSWORD, "New-password")
        with self.assertRaises(AccountError):
            auth.authorize(token)
        with self.assertRaises(AccountError):
            self.database.verify_password("001234", PASSWORD)
        token = auth.login("001234", "New-password")["token"]
        self.database.reset_password("001234")
        with self.assertRaises(AccountError):
            auth.authorize(token)
        self.assertEqual(self.database.verify_password("001234", "12345678"), 3)

    def test_teacher_reset_command(self):
        args = ["accounts.py", "--db", str(self.database.path), "reset", "--student-account", "001234"]
        with patch("sys.argv", args), patch("getpass.getpass", side_effect=AssertionError("重置无需输入密码")), patch("builtins.print"):
            self.assertEqual(accounts_main(), 0)
        self.assertEqual(self.database.verify_password("001234", "12345678"), 2)

    def test_teacher_reset_unknown_account_does_not_create_student(self):
        args = ["accounts.py", "--db", str(self.database.path), "reset", "--student-account", "unknown"]
        with patch("sys.argv", args), patch("getpass.getpass", side_effect=AssertionError("重置无需输入密码")), patch("builtins.print"):
            self.assertEqual(accounts_main(), 1)
        self.assertEqual(self.database.verify_password("001234", PASSWORD), 1)
        self.assertIsNone(self.database.get_student("unknown"))


class AuthenticationHTTPTests(unittest.TestCase):
    def setUp(self):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ARTIFACTS)
        self.root = Path(self.temporary.name)
        self.server = ReceiverServer(self.root / "received", host="127.0.0.1", port=0,
                                     accounts_db=self.root / "students.sqlite3")
        self.server.accounts.add_student("001234", PASSWORD)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.assertTrue(self.server.serving.wait(2))
        self.port = self.server.server_port
        self.archive = self.root / "作业.zip"
        with zipfile.ZipFile(self.archive, "w", zipfile.ZIP_DEFLATED) as stream:
            stream.writestr("main.py", "print('hello class')\n")
        data = self.archive.read_bytes()
        self.submission = Submission("001234", self.archive.name, len(data), hashlib.sha256(data).hexdigest())

    def tearDown(self):
        self.server.close()
        self.thread.join(5)
        self.temporary.cleanup()

    def login(self, password=PASSWORD):
        return login_student("127.0.0.1", "001234", password, port=self.port)

    def request(self, method, path, headers=None, body=b""):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_login_requires_database_password(self):
        with self.assertRaises(TransferError) as error:
            self.login("wrong")
        self.assertEqual(error.exception.status, 401)
        self.assertEqual(self.login()["student_account"], "001234")

    def test_data_endpoints_require_login(self):
        headers = {METADATA_HEADER: self.submission.encode(), "Content-Type": "application/octet-stream"}
        for method, path in (("GET", "/status"), ("POST", "/upload"), ("POST", "/activity")):
            body = self.archive.read_bytes() if method == "POST" else b""
            status, _ = self.request(method, path, headers, body)
            self.assertEqual(status, 401)
        self.assertEqual(list(self.server.storage.root.iterdir()), [])

    def test_cannot_submit_for_another_student(self):
        token = self.login()["token"]
        other = Submission("999999", self.archive.name, self.submission.size, self.submission.sha256)
        headers = {METADATA_HEADER: other.encode(), "Content-Type": "application/octet-stream", **auth_headers(token)}
        status, _ = self.request("POST", "/upload", headers, self.archive.read_bytes())
        self.assertEqual(status, 403)

    def test_student_changes_password_and_logs_in_again(self):
        token = self.login()["token"]
        with self.assertRaises(TransferError):
            change_student_password("127.0.0.1", token, "wrong", "New-password", port=self.port)
        self.login()
        result = change_student_password("127.0.0.1", token, PASSWORD, "New-password", port=self.port)
        self.assertTrue(result["ok"])
        with self.assertRaises(TransferError):
            self.login()
        with self.assertRaises(TransferError):
            upload_file(self.archive, "001234", "127.0.0.1", port=self.port, session_token=token)
        self.assertTrue(self.login("New-password")["ok"])

    def test_teacher_reset_allows_new_password_only(self):
        token = self.login()["token"]
        self.server.accounts.reset_password("001234")
        with self.assertRaises(TransferError):
            self.login()
        with self.assertRaises(TransferError):
            upload_file(self.archive, "001234", "127.0.0.1", port=self.port, session_token=token)
        self.assertTrue(self.login("12345678")["ok"])
        status, _ = self.request("POST", "/auth/reset")
        self.assertEqual(status, 404)

    def test_upload_and_logout(self):
        token = self.login()["token"]
        status_file = self.root / "status.json"
        status_file.write_bytes(UsageSession("001234").encode())
        for _ in range(2):
            result = upload_file(self.archive, "001234", "127.0.0.1", port=self.port,
                                 session_token=token, status_file=status_file)
            self.assertTrue(result["ok"])
            received = self.server.storage.root / "001234" / self.archive.name
            self.assertEqual(received.read_bytes(), self.archive.read_bytes())
            for path in received.parent.glob(".programming-status-*.json"):
                json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((self.server.storage.root / "001234" / self.archive.name).read_bytes(), self.archive.read_bytes())
        logout_student("127.0.0.1", token, port=self.port)
        with self.assertRaises(TransferError):
            upload_file(self.archive, "001234", "127.0.0.1", port=self.port, session_token=token)


if __name__ == "__main__":
    unittest.main()
