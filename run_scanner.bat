@echo off
chcp 65001 >nul
title Phishing Detector - Cyber Threat Scanner
color 0B

echo ==============================================================================
echo    PHISHING DETECTOR - ADVANCED THREAT SCANNER (WINDOWS EDITION)
echo ==============================================================================
echo.
echo [*] Checking Python environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH! Please install Python 3.
    pause
    exit /b 1
)

echo [*] Starting Web Server & Launching Cyber UI in your Browser...
echo [*] URL: http://127.0.0.1:5000
echo.
echo Press Ctrl+C in this terminal whenever you wish to stop the server.
echo.

python web_app.py
pause
