@echo off
setlocal

cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    set "NOXLAB_PYTHON=.venv\Scripts\python.exe"
) else (
    set "NOXLAB_PYTHON=python"
)

"%NOXLAB_PYTHON%" ".\src\main.py"

if errorlevel 1 (
    echo.
    echo NOXLAB VAULT exited with an error.
    echo Install dependencies with:
    echo python -m pip install -r requirements.txt
    echo.
    pause
)
