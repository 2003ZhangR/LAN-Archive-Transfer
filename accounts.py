"""教师本地学生账号库：创建账号、验证密码、学生改密和教师重置。"""

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import argparse
import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3
import sys
import threading
import time

DEFAULT_DB = Path(__file__).resolve().parent / "teacher_data" / "students.sqlite3"
AUTH_FEATURE = "student-auth-v1"
SESSION_SECONDS = 8 * 60 * 60
RESET_PASSWORD = "12345678"


class AccountError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def validate_account(account: str):
    if (not isinstance(account, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", account)
            or re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", account, re.I)):
        raise AccountError("学号须为 1–32 位数字、字母、下划线或短横线，不能使用 Windows 保留名称。")


def validate_password(password: str):
    if not isinstance(password, str) or not password.strip() or len(password) > 128:
        raise AccountError("密码不能为空，且不能超过 128 个字符。")


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)


class AccountDatabase:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS students (
                student_account TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                credential_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            )""")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def add_student(self, account: str, password: str, name: str = ""):
        validate_account(account)
        validate_password(password)
        salt = secrets.token_bytes(16)
        try:
            with self.connect() as connection:
                connection.execute("""INSERT INTO students
                    (student_account, name, password_salt, password_hash, created_at)
                    VALUES (?, ?, ?, ?, ?)""",
                    (account, name, salt, password_hash(password, salt), datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError as exc:
            raise AccountError("该学号已存在。修改已有密码请使用重置命令。") from exc

    def list_students(self) -> list[dict]:
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT student_account, name FROM students ORDER BY student_account")]

    def get_student(self, account: str):
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM students WHERE student_account=?", (account,)).fetchone()
            return dict(row) if row is not None else None

    def verify_password(self, account: str, password: str) -> int:
        validate_account(account)
        validate_password(password)
        row = self.get_student(account)
        if row is None or not hmac.compare_digest(password_hash(password, row["password_salt"]), row["password_hash"]):
            raise AccountError("账号或密码错误。", 401)
        return row["credential_version"]

    def _set_password(self, account: str, password: str, *, expected_version: int | None = None):
        validate_account(account)
        validate_password(password)
        salt = secrets.token_bytes(16)
        digest = password_hash(password, salt)
        query = """UPDATE students SET password_salt=?, password_hash=?,
                   credential_version=credential_version+1 WHERE student_account=?"""
        values = [salt, digest, account]
        if expected_version is not None:
            query += " AND credential_version=?"
            values.append(expected_version)
        with self.connect() as connection:
            if connection.execute(query, values).rowcount != 1:
                raise AccountError("学号不存在或密码已变更，请重新登录。")

    def change_password(self, account: str, old_password: str, new_password: str):
        version = self.verify_password(account, old_password)
        self._set_password(account, new_password, expected_version=version)

    def reset_password(self, account: str):
        self._set_password(account, RESET_PASSWORD)


class Authenticator:
    def __init__(self, database: AccountDatabase):
        self.database = database
        self.sessions = {}
        self.lock = threading.Lock()

    def login(self, account: str, password: str) -> dict:
        version = self.database.verify_password(account, password)
        token = secrets.token_urlsafe(32)
        expiry = time.time() + SESSION_SECONDS
        with self.lock:
            self.sessions = {key: value for key, value in self.sessions.items() if value[1] > time.time()}
            self.sessions[token] = (account, expiry, version)
        return dict(ok=True, student_account=account, token=token,
                    expires_at=datetime.fromtimestamp(expiry, timezone.utc).isoformat(timespec="seconds"))

    def authorize(self, token: str, account: str | None = None) -> str:
        with self.lock:
            session = self.sessions.get(token)
        if session is None or session[1] <= time.time():
            raise AccountError("登录已失效，请重新登录。", 401)
        row = self.database.get_student(session[0])
        if row is None or row["credential_version"] != session[2]:
            raise AccountError("密码已修改或重置，请重新登录。", 401)
        if account is not None and account != session[0]:
            raise AccountError("登录学号与提交学号不一致。", 403)
        return session[0]

    def logout(self, token: str):
        with self.lock:
            self.sessions.pop(token, None)


def input_new_password() -> str:
    password = getpass.getpass("输入新密码：")
    if password != getpass.getpass("再次输入新密码："):
        raise AccountError("两次密码不一致，未保存。")
    validate_password(password)
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description="教师本地管理学生账号")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="账号 SQLite 数据库路径")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="创建空账号库")
    commands.add_parser("list", help="列出学生账号")
    for verb, help_text in (("add", "创建学生账号"), ("reset", "忘记密码时由教师重置")):
        command = commands.add_parser(verb, help=help_text)
        command.add_argument("--student-account", required=True)
        if verb == "add":
            command.add_argument("--name", default="")
    args = parser.parse_args()
    try:
        database = AccountDatabase(args.db)
        if args.command == "init":
            print(f"账号库已创建：{database.path}")
        elif args.command == "list":
            for row in database.list_students():
                print(f"{row['student_account']}\t{row['name']}")
        else:
            validate_account(args.student_account)
            if args.command == "reset" and database.get_student(args.student_account) is None:
                raise AccountError("该学号不存在。")
            if args.command == "add":
                password = input_new_password()
                database.add_student(args.student_account, password, args.name)
                print(f"已创建账号：{args.student_account}")
            else:
                database.reset_password(args.student_account)
                print(f"已重置账号 {args.student_account} 的密码为 {RESET_PASSWORD}。")
    except (AccountError, OSError, sqlite3.Error) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("已取消。", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
