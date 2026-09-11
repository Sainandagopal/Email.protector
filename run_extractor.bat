@echo off
echo ========================================================
echo   Gmail Sender-IP Extractor
echo ========================================================
cd /d "%~dp0"

set PYTHON_CMD=python
if exist "%~dp0backend\.venv\Scripts\python.exe" (
    set PYTHON_CMD="%~dp0backend\.venv\Scripts\python.exe"
)

%PYTHON_CMD% -u gmail_ip_extractor.py
pause
