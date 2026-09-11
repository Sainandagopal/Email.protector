@echo off
echo ========================================================
echo   SIH-Guard: Starting React SOC Dashboard (Port 5173)
echo ========================================================
cd /d "%~dp0"

set PYTHON_CMD=python
if exist "%~dp0backend\.venv\Scripts\python.exe" (
    set PYTHON_CMD="%~dp0backend\.venv\Scripts\python.exe"
)

%PYTHON_CMD% -u serve_dashboard.py
pause
