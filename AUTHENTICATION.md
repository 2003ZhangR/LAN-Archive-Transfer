# 学生账号与密码

教师端使用 SQLite，数据库默认在项目的 `teacher_data/students.sqlite3`。学生通过教师端验证账号密码，不直接访问数据库文件。

## 教师端

在项目目录执行（也可把 `python` 替换为 `.\.venv\Scripts\python.exe`）：

```powershell
python accounts.py add --student-account 20260001 --name "张三"
python accounts.py list
python upload.py receive --save-dir ".\接收作业"
```

创建账号时隐藏输入两次初始密码。学号保留前导零，重复学号不会覆盖已有账号。

学生忘记密码时，教师在本机执行：

```powershell
python accounts.py reset --student-account 20260001
```

执行后直接将密码重置为 `12345678`，无需输入旧密码或新密码。学生使用 `12345678` 登录后，可自行修改密码。重置后该学号原有登录会话失效。

自定义账号库时，两端管理命令指向相同文件：

```powershell
python accounts.py --db "D:\教师数据\students.sqlite3" reset --student-account 20260001
python upload.py receive --save-dir ".\接收作业" --accounts-db "D:\教师数据\students.sqlite3"
```

## 学生端

双击 `启动学生端.cmd`，或运行 `python student_client.py`，填写教师 IP、学号和密码。只有账号密码与教师数据库一致才能进入学生界面。

登录后点击右上角“修改密码”，填写旧密码、新密码、确认新密码。旧密码错误或两次新密码不一致时不更新。成功后停止当前监控、保存日志并返回登录页，学生使用新密码重新登录。作业和已有日志保留。

密码不能为空，最多 128 个字符；不额外设置复杂度、首次强制修改或错误次数锁定规则。数据库保存独立随机盐和 PBKDF2-SHA256 密码哈希，不保存明文密码。

教师账号管理只有本机命令行入口。学生只能修改自己账号的密码；作业和日志接口仍检查登录身份与学号。退出登录、修改或重置密码后，旧会话不能继续提交。

沿用项目现有的局域网 HTTP 通信，传输尚未加密。数据库和 `teacher_data` 目录只保存在教师电脑，不随学生程序分发。

## 编程接口与测试

先用 `login_student(ip, account, password)` 登录，把返回的 `token` 传入 `upload_file(..., session_token=token)`。命令行 `upload.py send` 会隐藏询问密码，再上传。

```powershell
python -m unittest discover -s test -v
```
