@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
if not exist "python.exe" (
  echo Packaged python.exe was not found. Extract the WHOLE validation ZIP first.
  pause
  exit /b 2
)
"%~dp0python.exe" -I -S -B "%~dp0tools\windows_validation_runner.py"
set "CHECK_EXIT=%ERRORLEVEL%"
echo.
echo Check process exit code: %CHECK_EXIT%
echo Review RESULT.json and RESULT.txt in the results folder.
echo An automatic PASS does not complete manual Stage 9 or equipment Stage 10.
pause
exit /b %CHECK_EXIT%
