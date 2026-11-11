@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 goto no_python
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 goto no_python
if not exist ".venv\Scripts\python.exe" py -3 -m venv .venv
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -c "import tkinter, socket, select; print('Python and Tkinter are ready.')"
if errorlevel 1 goto failed
echo Setup complete. Run start.cmd. No pip packages or internet access are needed.
pause
exit /b 0
:no_python
echo Install Python 3.11 or newer with Python Launcher and Tcl/Tk.
pause
exit /b 1
:failed
echo Setup failed. Check the error above and ensure Tcl/Tk is installed.
pause
exit /b 1
