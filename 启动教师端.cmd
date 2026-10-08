@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" teacher_client.py %*
) else (
    python teacher_client.py %*
)
if errorlevel 1 pause
