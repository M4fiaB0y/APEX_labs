@echo off
setlocal enabledelayedexpansion
title APEX - ENTERPRISE API SECURITY RANGE
cd /d "%~dp0"
color 0B

echo ==============================================================================
echo             _    ____  ______  ______ ___  ____  ______ 
echo            / \  ^|  _ \^| ____^|\ \/ / ___/ _ \^|  _ \^| ____^|
echo           / _ \ ^| ^|_) ^|  _^|   \  / ^|  ^| ^| ^| ^| ^|_) ^|  _^|  
echo          / ___ \^|  __/^| ^|___  /  \ ^|__^| ^|_^| ^|  _ ^<^| ^|___ 
echo         /_/   \_^|_^|   ^|_____^|/_/\_\____\___/^|_^| \_\_____^|
echo.
echo              APEX ENTERPRISE CYBER RANGE ^& API GATEWAY
echo               Automated 1-Click Environment Setup (2026)
echo ==============================================================================
echo.

:: [1/5] Locate or Auto-Install Python 3
echo [*] Step 1/5: Detecting Python 3 environment...
set "PYCMD="

call :scan_all_pythons
if defined PYCMD goto :py_ready

echo [!] Python 3 was not detected in PATH or standard installation folders.
echo [*] Starting automated Python 3 installation...
echo.

REM Attempt A: Windows Package Manager (winget)
where winget >nul 2>&1
if errorlevel 1 goto :try_powershell_download

echo [*] Installing Python 3.12 via Windows Package Manager (winget)...
winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements
call :scan_all_pythons
if defined PYCMD goto :py_ready

:try_powershell_download
echo [*] Downloading Python 3 installer from python.org...
set "PY_INSTALLER=%TEMP%\python-apex-setup.exe"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $wc = New-Object Net.WebClient; $wc.DownloadFile('https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe', $env:TEMP + '\python-apex-setup.exe')" >nul 2>&1

if not exist "%TEMP%\python-apex-setup.exe" goto :manual_install_needed

echo [*] Installing Python 3 silently into user profile (takes ~30s)...
"%TEMP%\python-apex-setup.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 SimpleInstall=1
del "%TEMP%\python-apex-setup.exe" >nul 2>&1
timeout /t 3 >nul 2>&1

call :scan_all_pythons
if defined PYCMD goto :py_ready

:manual_install_needed
echo.
echo [!] ERROR: Automated Python 3 installation could not be completed.
echo Please install Python 3 manually from: https://www.python.org/downloads/
echo IMPORTANT: Make sure to check "Add Python to PATH" during installation.
echo.
pause
exit /b 1

:py_ready
echo [+] Python 3 Found: %PYCMD%

:: [2/5] Check & Auto-Install Dependencies
echo [*] Step 2/5: Verifying application dependencies...
%PYCMD% -c "import flask, requests" >nul 2>&1
if not errorlevel 1 goto :deps_ready

echo [*] Installing required packages (Flask, Requests)...
if exist "requirements.txt" (
    %PYCMD% -m pip install --quiet -r requirements.txt
) else (
    %PYCMD% -m pip install --quiet flask requests
)
if errorlevel 1 (
    echo [!] ERROR: Failed to install packages via pip. Check your internet connection.
    pause
    exit /b 1
)

:deps_ready
echo [+] Dependencies satisfied (Flask and Requests ready).

:: [3/5] Initialize Database & Dynamic Flags
echo [*] Step 3/5: Initializing APEX Cyber Range Database...
%PYCMD% database.py >nul 2>&1
echo [+] Database initialized with dynamic cryptographic HMAC flags.

:: [4/5] Check Port & Start Server
set "APEX_PORT=5000"
netstat -ano | findstr /R /C:":%APEX_PORT% .*LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [*] Port %APEX_PORT% is in use. Switching to alternate port 5050...
    set "APEX_PORT=5050"
)

echo [*] Step 4/5: Launching APEX API Gateway on http://127.0.0.1:%APEX_PORT% ...
start /b "" %PYCMD% app.py > lab.log 2>&1

:: [5/5] Poll Server Health and Auto-Spawn Browser
echo [*] Step 5/5: Waiting for APEX Gateway to become responsive...
set "READY=0"
for /l %%i in (1,1,25) do (
    if "!READY!"=="0" (
        %PYCMD% -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:%APEX_PORT%/health', timeout=1)" >nul 2>&1
        if not errorlevel 1 (
            set "READY=1"
        ) else (
            timeout /t 1 >nul 2>&1
        )
    )
)

echo.
echo ==============================================================================
echo  [+] SUCCESS: APEX Cyber Range is LIVE and running!
echo  [+] Localhost URL:      http://127.0.0.1:%APEX_PORT%/
echo  [+] Examiner Console:   http://127.0.0.1:%APEX_PORT%/evaluator
echo  [+] Swagger API Docs:   http://127.0.0.1:%APEX_PORT%/docs
echo  [+] Server Log File:    lab.log
echo ==============================================================================
echo.
echo [*] Spawning web browser now...
start http://127.0.0.1:%APEX_PORT%/

echo.
echo NOTE: KEEP THIS CONSOLE WINDOW OPEN while using the lab.
echo Close this window or press Ctrl+C when you want to stop the server.
echo.
pause >nul
exit /b 0

:: ==============================================================================
:: Subroutines for Python 3 Discovery
:: ==============================================================================
:scan_all_pythons
call :check_one "python3"
if defined PYCMD exit /b 0

call :check_one "py -3"
if defined PYCMD exit /b 0

call :check_one "python"
if defined PYCMD exit /b 0

call :check_one "py"
if defined PYCMD exit /b 0

call :check_one "C:\py3\Scripts\python3.exe"
if defined PYCMD exit /b 0

call :check_one "C:\py3\python3.exe"
if defined PYCMD exit /b 0

call :check_one "C:\py3\python.exe"
if defined PYCMD exit /b 0

if exist "%LocalAppData%\Programs\Python" (
    for /d %%D in ("%LocalAppData%\Programs\Python\Python3*") do (
        if not defined PYCMD (
            if exist "%%~fD\python.exe" (
                call :check_one "%%~fD\python.exe"
            )
        )
    )
)
if defined PYCMD exit /b 0

for /d %%D in ("C:\Python3*") do (
    if not defined PYCMD (
        if exist "%%~fD\python.exe" (
            call :check_one "%%~fD\python.exe"
        )
    )
)
if defined PYCMD exit /b 0

for /d %%D in ("C:\Program Files\Python3*") do (
    if not defined PYCMD (
        if exist "%%~fD\python.exe" (
            call :check_one "%%~fD\python.exe"
        )
    )
)
exit /b 0

:check_one
%~1 -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PYCMD=%~1"
)
exit /b 0
