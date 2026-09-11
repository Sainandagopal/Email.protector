@echo off
echo ========================================================
echo   SIH-Guard: Starting Cyber-Forensics Platform
echo ========================================================
echo   * SOC Dashboard: http://localhost:8000
echo   * API Docs:      http://localhost:8000/docs
echo   * Health Check:  http://localhost:8000/api/v1/health
echo ========================================================
cd /d "%~dp0"
set PYTHONPATH=%~dp0backend

set PYTHON_CMD=python
if exist "%~dp0backend\.venv\Scripts\python.exe" (
    set PYTHON_CMD="%~dp0backend\.venv\Scripts\python.exe"
)

%PYTHON_CMD% -u run_platform.py
pause
