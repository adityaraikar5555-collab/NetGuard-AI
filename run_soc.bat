@echo off
title NetGuard AI - Cyber Security Operations Center
echo ======================================================================
echo           NetGuard AI — SOC Command Center & Backend Launcher
echo ======================================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment .venv not found.
    echo Please create it or install dependencies via:
    echo   python -m venv .venv
    echo   .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

echo [1/2] Starting FastAPI Intelligence Backend on port 8000...
start "NetGuard Backend (FastAPI)" cmd /k ".venv\Scripts\python.exe -m uvicorn frontend.app:app --host 127.0.0.1 --port 8000"

timeout /t 3 /nobreak >nul

echo [2/2] Launching Streamlit SOC Dashboard on port 8501...
start "NetGuard SOC Dashboard (Streamlit)" cmd /k ".venv\Scripts\streamlit.exe run frontend/dashboard.py"

echo.
echo ======================================================================
echo NetGuard AI SOC is running!
echo - API Backend: http://127.0.0.1:8000/docs
echo - Streamlit Dashboard: http://localhost:8501
echo ======================================================================
echo.
