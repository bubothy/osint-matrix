@echo off
setlocal
cd /d "%~dp0"
title OSINT MATRIX - setup
echo.
echo  ============================================
echo    OSINT MATRIX - first-time setup
echo  ============================================
echo.

set "PY=py -3"
where py >nul 2>nul
if errorlevel 1 set "PY=python"

%PY% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if errorlevel 1 goto :nopython

echo  [1/4] Creating virtual environment...
if not exist ".venv\Scripts\python.exe" (
    %PY% -m venv .venv
    if errorlevel 1 goto :failed
) else (
    echo        .venv already exists - reusing it.
)

echo  [2/4] Installing dependencies...
call ".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
call ".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :failed

echo  [3/4] Preparing configuration...
if not exist ".env" (
    copy /y ".env.example" ".env" >nul
    echo        Created .env - open it and fill DISCORD_TOKEN and OWNER_IDS.
) else (
    echo        .env already exists - leaving it untouched.
)

echo  [4/4] Verifying the codebase...
call ".venv\Scripts\python.exe" -c "import compileall,sys; ok = compileall.compile_file('bot.py', quiet=1) and compileall.compile_file('config.py', quiet=1) and compileall.compile_dir('core', quiet=1) and compileall.compile_dir('cogs', quiet=1); sys.exit(0 if ok else 1)"
if errorlevel 1 goto :failed

echo.
echo  Setup complete.
echo  Next: edit .env, then double-click run.bat
echo.
pause
exit /b 0

:nopython
echo.
echo  [X] Python 3.11 or newer was not found.
echo      Install it from https://www.python.org/downloads/windows/
echo      During installation tick "Add python.exe to PATH".
echo.
pause
exit /b 1

:failed
echo.
echo  [X] Setup failed. Scroll up and read the first error line.
echo.
pause
exit /b 1
