@echo off
REM Console de triage des vulnerabilites - acces depuis le telephone.
REM Ouvre l'application sur le reseau local (meme Wi-Fi). Aucun mot de passe :
REM a n'utiliser que sur un reseau de confiance, et a fermer apres usage.

cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
    py app.py --lan %*
) else (
    python app.py --lan %*
)

if %errorlevel% neq 0 (
    echo.
    echo L'application s'est arretee avec une erreur.
    pause
)
