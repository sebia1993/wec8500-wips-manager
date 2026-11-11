@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" app.py
) else (
  where py >nul 2>&1
  if errorlevel 1 (
    echo Python not found. Run install.cmd after installing Python 3.11 or newer.
    pause
    exit /b 1
  )
  py -3 app.py
)
if errorlevel 1 pause
