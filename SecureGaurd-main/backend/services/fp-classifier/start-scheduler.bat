@echo off
title SecureGuard — Retrain Scheduler
echo ============================================================
echo  SecureGuard Retrain Scheduler — Starting
echo ============================================================
cd /d "%~dp0"

if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

echo [INFO] Scheduler will run retrain every 24 hours (configurable via .env)
echo [INFO] Logs: %~dp0scheduler.log
echo.
python scheduler.py
pause
