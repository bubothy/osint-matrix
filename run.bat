@echo off
setlocal
cd /d "%~dp0"
title OSINT MATRIX
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo  [X] No virtual environment found. Run install.bat first.
    echo.
    pause
    exit /b 1
)

if not exist ".env" (
    echo.
    echo  [X] No .env found. Copy .env.example to .env and fill it in.
    echo.
    pause
    exit /b 1
)

echo.
echo  Starting OSINT MATRIX... press Ctrl+C to stop.
echo.
call ".venv\Scripts\python.exe" bot.py
set "CODE=%errorlevel%"
echo.
if not "%CODE%"=="0" (
    echo  Bot exited with code %CODE%. Check logs\bot.log for details.
) else (
    echo  Bot stopped cleanly.
)
echo.
pause
exit /b %CODE%
