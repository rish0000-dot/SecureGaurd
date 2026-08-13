@echo off
title SecureGuard — FP Classifier Service
echo ============================================================
echo  SecureGuard FP Classifier — Starting on port 8001
echo ============================================================
cd /d "%~dp0"

:: Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo [INFO] No venv found — using system Python
)

:: Install/upgrade dependencies
echo [INFO] Installing dependencies...
pip install -r requirements.txt --quiet

echo [INFO] Starting FastAPI service...
echo [INFO] API docs: http://localhost:8001/docs
echo [INFO] Health:   http://localhost:8001/health
echo.
uvicorn service:app --host 0.0.0.0 --port 8001 --reload
pause
