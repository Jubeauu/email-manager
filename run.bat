@echo off
REM Lance l'application Email Manager en local.
cd /d "%~dp0"

if not exist ".venv\" (
    echo [Email Manager] Creation de l'environnement Python...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    echo [Email Manager] Installation des dependances...
    python -m pip install --upgrade pip >nul
    python -m pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

echo.
echo ============================================================
echo   Email Manager demarre sur  http://127.0.0.1:8000
echo   (Ctrl+C pour arreter)
echo ============================================================
echo.

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
