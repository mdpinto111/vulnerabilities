@echo off
REM Vulnerability triage console - access from a phone.
REM Opens the application on the local network (same Wi-Fi). No password:
REM only use it on a trusted network, and close it after use.

cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
    py app.py --lan %*
) else (
    python app.py --lan %*
)

if %errorlevel% neq 0 (
    echo.
    echo The application stopped with an error.
    pause
)
