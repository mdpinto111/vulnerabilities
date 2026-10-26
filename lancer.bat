@echo off
REM Vulnerability triage console - Windows launcher
REM Double-click this file to start the application.

cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
    py app.py %*
) else (
    python app.py %*
)

if %errorlevel% neq 0 (
    echo.
    echo The application stopped with an error.
    pause
)
