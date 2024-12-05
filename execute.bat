@echo off
setlocal enabledelayedexpansion

set "PYTHON_VERSION=3.11.0"
set "VENV_DIR=.venv"
set "PYTHON=%VENV_DIR%\Scripts\python.exe"
set "PIP=%VENV_DIR%\Scripts\pip.exe"
set "CVES_FILE=cve.txt"

:help
if "%1"=="help" (
    echo Available commands:
    echo   all              - Set up the complete development environment
    echo   check-python     - Verify Python installation
    echo   create-venv      - Create Python virtual environment
    echo   install-deps     - Install/update project dependencies
    echo   clean           - Remove virtual environment and temporary files
    echo   check-g4f       - Check and update g4f package if needed
    echo   show-versions   - Display installed and latest g4f versions
    echo   run             - Run the application with optional CVE file
    exit /b 0
)

if "%1"=="" goto help
if "%1"=="all" goto all
if "%1"=="check-python" goto check-python
if "%1"=="create-venv" goto create-venv
if "%1"=="install-deps" goto install-deps
if "%1"=="clean" goto clean
if "%1"=="check-g4f" goto check-g4f
if "%1"=="show-versions" goto show-versions
if "%1"=="run" goto run

:all
call :check-python
call :create-venv
call :install-deps
echo Setup complete! Use 'cmd /c execute.bat run' to start the application.
exit /b 0

:check-python
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found. Installing Python...
    call :install-python
) else (
    for /f "tokens=2" %%I in ('python --version 2^>^&1') do echo Python %%I found.
)
exit /b 0

:install-python
where winget >nul 2>&1
if errorlevel 1 (
    echo Error: winget not found. Please install Python %PYTHON_VERSION% manually from python.org
    exit /b 1
) else (
    winget install -e --id Python.Python.3.11
    echo Installed Python %PYTHON_VERSION%
)
exit /b 0

:create-venv
echo Setting up virtual environment...
if not exist "%VENV_DIR%" (
    python -m venv %VENV_DIR%
    echo Virtual environment created successfully.
) else (
    echo Virtual environment already exists.
)
exit /b 0

:install-deps
call :create-venv
echo Installing/updating dependencies...
call %PIP% install --upgrade pip
call %PIP% install -r requirements.txt
echo All dependencies are up to date!
exit /b 0

:clean
echo Cleaning up...
if exist "%VENV_DIR%" (
    rmdir /s /q "%VENV_DIR%"
)
echo Cleanup complete!
exit /b 0

:check-g4f
for /f "tokens=2" %%I in ('call %PIP% show g4f ^| findstr "Version:"') do set "INSTALLED_VERSION=%%I"
for /f "tokens=*" %%I in ('python -c "import json,urllib.request; print(json.loads(urllib.request.urlopen('https://pypi.org/pypi/g4f/json').read())['info']['version'])"') do set "LATEST_VERSION=%%I"

echo Installed version: %INSTALLED_VERSION%
echo Latest version: %LATEST_VERSION%

if not "%INSTALLED_VERSION%"=="%LATEST_VERSION%" (
    echo Updating g4f to latest version...
    call %PIP% install --upgrade g4f
) else (
    echo g4f is already at the latest version.
)
exit /b 0

:show-versions
call :check-g4f
exit /b 0

:run
echo Checking g4f compatibility
call :check-g4f
set "input_file="
set /p "input_file=Enter the path to the CVE file (default: %CVES_FILE%): "
if "%input_file%"=="" set "input_file=%CVES_FILE%"
echo Running with file: %input_file%
call %PYTHON% src/server.py "%input_file%"
exit /b 0
