@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" student_client.py %*
) else (
    python student_client.py %*
)
if errorlevel 1 pause
