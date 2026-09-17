@echo off
REM Console de triage des vulnerabilites - lanceur Windows
REM Double-cliquez sur ce fichier pour demarrer l'application.

cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
    py app.py %*
) else (
    python app.py %*
)

if %errorlevel% neq 0 (
    echo.
    echo L'application s'est arretee avec une erreur.
    pause
)
