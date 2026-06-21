@echo off
setlocal

title NOXLAB VAULT Setup
cd /d "%~dp0"

echo.
echo ==========================================
echo        NOXLAB VAULT - Windows Setup
echo ==========================================
echo.

if not exist "requirements.txt" (
    echo ERROR: requirements.txt was not found.
    echo Run this setup file from the NOXLAB VAULT project folder.
    echo.
    pause
    exit /b 1
)

if exist ".venv\Scripts\python.exe" (
    set "BOOTSTRAP_PYTHON=.venv\Scripts\python.exe"
    goto :create_venv
)

where py >nul 2>nul
if not errorlevel 1 (
    set "BOOTSTRAP_PYTHON=py -3"
    goto :create_venv
)

where python >nul 2>nul
if not errorlevel 1 (
    set "BOOTSTRAP_PYTHON=python"
    goto :create_venv
)

echo ERROR: Python was not found.
echo Install Python 3.10 or newer from https://www.python.org/downloads/windows/
echo Make sure "Add python.exe to PATH" is enabled during install.
echo.
pause
exit /b 1

:create_venv
if not exist ".venv\Scripts\python.exe" (
    echo Creating local virtual environment...
    %BOOTSTRAP_PYTHON% -m venv ".venv"
    if errorlevel 1 (
        echo ERROR: Failed to create the virtual environment.
        echo.
        pause
        exit /b 1
    )
) else (
    echo Local virtual environment already exists.
)

set "APP_PYTHON=.venv\Scripts\python.exe"

echo.
echo Upgrading pip...
"%APP_PYTHON%" -m pip install --upgrade pip
if errorlevel 1 (
    echo ERROR: Failed to upgrade pip.
    echo.
    pause
    exit /b 1
)

echo.
echo Installing required packages...
"%APP_PYTHON%" -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install required packages.
    echo.
    pause
    exit /b 1
)

echo.
echo Verifying required packages...
"%APP_PYTHON%" -c "import cryptography, argon2, tkinter; print('cryptography, argon2-cffi, and tkinter are installed')"
if errorlevel 1 (
    echo ERROR: Dependency verification failed.
    echo.
    pause
    exit /b 1
)

echo.
echo Creating shortcuts...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$project = (Resolve-Path '.').Path; " ^
    "$launcher = Join-Path $project 'NOXLAB VAULT.vbs'; " ^
    "$icon = Join-Path $project 'assets\noxlab_vault.ico'; " ^
    "if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw \"Launcher missing: $launcher\" }; " ^
    "if (-not (Test-Path -LiteralPath $icon -PathType Leaf)) { throw \"Icon missing: $icon\" }; " ^
    "$desktop = [Environment]::GetFolderPath('DesktopDirectory'); " ^
    "$targets = @((Join-Path $desktop 'NOXLAB VAULT.lnk'), (Join-Path $project 'NOXLAB VAULT.lnk')); " ^
    "$shell = New-Object -ComObject WScript.Shell; " ^
    "foreach ($path in $targets) { $shortcut = $shell.CreateShortcut($path); $shortcut.TargetPath = $launcher; $shortcut.WorkingDirectory = $project; $shortcut.IconLocation = \"$icon,0\"; $shortcut.Description = 'Start NOXLAB VAULT'; $shortcut.Save(); Write-Output \"Shortcut: $path\" }"
if errorlevel 1 (
    echo ERROR: Failed to create shortcuts.
    echo.
    pause
    exit /b 1
)

echo.
echo Setup complete.
echo.
echo Start NOXLAB VAULT with the Desktop shortcut.
echo.
echo Console fallback:
echo   NOXLAB VAULT.cmd
echo.
pause
exit /b 0
