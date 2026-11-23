#!/usr/bin/env bash
# ==============================================================================
#             _    ____  ______  ______ ___  ____  ______ 
#            / \  |  _ \| ____|\ \/ / ___/ _ \|  _ \| ____|
#           / _ \ | |_) |  _|   \  / |  | | | | |_) |  _|  
#          / ___ \|  __/| |___  /  \ |__| |_| |  _ <| |___ 
#         /_/   \_\_|   |_____|/_/\_\____\___/|_| \_\_____|
#
#              APEX ENTERPRISE CYBER RANGE & API GATEWAY
#               Linux / macOS 1-Click Automated Setup
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================================================="
echo "          APEX ENTERPRISE API SECURITY RANGE (2026 EDITION)                    "
echo "              Automated Linux / macOS Setup & Launch Engine                   "
echo "=============================================================================="
echo ""

# 1. Detect or Install Python 3
echo "[*] Step 1/5: Detecting Python 3 environment..."
PYCMD=""

if command -v python3 >/dev/null 2>&1 && python3 -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" 2>/dev/null; then
    PYCMD="python3"
elif command -v python >/dev/null 2>&1 && python -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" 2>/dev/null; then
    PYCMD="python"
fi

if [ -z "$PYCMD" ]; then
    echo "[!] Python 3 not found. Attempting automatic installation..."
    if command -v apt-get >/dev/null 2>&1; then
        echo "[*] Installing Python 3 via apt..."
        sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
        PYCMD="python3"
    elif command -v dnf >/dev/null 2>&1; then
        echo "[*] Installing Python 3 via dnf..."
        sudo dnf install -y python3 python3-pip
        PYCMD="python3"
    elif command -v pacman >/dev/null 2>&1; then
        echo "[*] Installing Python 3 via pacman..."
        sudo pacman -S --noconfirm python python-pip
        PYCMD="python3"
    elif command -v brew >/dev/null 2>&1; then
        echo "[*] Installing Python 3 via Homebrew..."
        brew install python3
        PYCMD="python3"
    else
        echo "[!] ERROR: Unable to auto-install Python 3. Please install Python 3 manually."
        exit 1
    fi
fi

echo "[+] Python 3 detected: $PYCMD ($($PYCMD --version))"

# 2. Setup Virtual Environment & Install Dependencies
echo "[*] Step 2/5: Setting up environment and dependencies..."
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment in $VENV_DIR..."
    $PYCMD -m venv "$VENV_DIR" 2>/dev/null || true
fi

if [ -f "$VENV_DIR/bin/python" ]; then
    ACTIVE_PY="$VENV_DIR/bin/python"
    ACTIVE_PIP="$VENV_DIR/bin/pip"
else
    ACTIVE_PY="$PYCMD"
    ACTIVE_PIP="$PYCMD -m pip"
fi

if ! $ACTIVE_PY -c "import flask, requests, graphql" 2>/dev/null; then
    echo "[*] Installing required packages (Flask, Requests, GraphQL-core)..."
    if [ -f "requirements.txt" ]; then
        $ACTIVE_PIP install --quiet -r requirements.txt 2>/dev/null || $ACTIVE_PIP install --quiet --break-system-packages -r requirements.txt || {
            echo "[!] ERROR: Failed to install dependencies via pip. Please check network connection."
            exit 1
        }
    else
        $ACTIVE_PIP install --quiet flask requests graphql-core 2>/dev/null || $ACTIVE_PIP install --quiet --break-system-packages flask requests graphql-core || {
            echo "[!] ERROR: Failed to install dependencies via pip. Please check network connection."
            exit 1
        }
    fi
fi
echo "[+] Dependencies verified."

# 3. Initialize SQLite Database with dynamic HMAC flags
echo "[*] Step 3/5: Initializing APEX Cyber Range Database..."
if ! $ACTIVE_PY database.py > lab_init.log 2>&1; then
    echo ""
    echo "[!] ERROR: Database initialization failed!"
    echo "[!] Log output from lab_init.log:"
    echo "------------------------------------------------------------------------------"
    cat lab_init.log 2>/dev/null || true
    echo "------------------------------------------------------------------------------"
    rm -f lab_init.log
    exit 1
fi
rm -f lab_init.log
echo "[+] Database seeded successfully with dynamic cryptographic flags."

# 4. Check Port & Start Server in background
echo "[*] Detecting available local loopback port..."
APEX_PORT=$($ACTIVE_PY -c "import database; print(database.find_free_port())" 2>/dev/null || echo 5000)
echo "[*] Selected local port: $APEX_PORT"

export APEX_PORT
echo "[*] Step 4/5: Launching APEX API Gateway on http://127.0.0.1:${APEX_PORT} ..."
$ACTIVE_PY app.py > lab.log 2>&1 &
SERVER_PID=$!

# Trap signals to gracefully terminate the server on exit
cleanup() {
    echo ""
    echo "[*] Shutting down APEX Cyber Range server (PID: $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    echo "[+] APEX server stopped."
}
trap cleanup INT TERM EXIT

# 5. Poll Server Health and Open Browser
echo "[*] Step 5/5: Waiting for APEX Gateway to become responsive..."
READY=0
for i in {1..25}; do
    if curl -s -f "http://127.0.0.1:${APEX_PORT}/health" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    echo ""
    echo "=============================================================================="
    echo " [!] ERROR: APEX Cyber Range failed to start or health check timed out."
    echo " [!] Target URL: http://127.0.0.1:${APEX_PORT}/health"
    echo "=============================================================================="
    echo ""
    echo "[*] Showing recent application output from lab.log:"
    echo "------------------------------------------------------------------------------"
    if [ -f "lab.log" ]; then
        cat "lab.log"
    else
        echo "(No lab.log file found)"
    fi
    echo "------------------------------------------------------------------------------"
    echo ""
    echo "Please resolve the errors shown above and re-run start_lab.sh."
    exit 1
fi

echo ""
echo "=============================================================================="
echo " [+] SUCCESS: APEX Cyber Range is LIVE and running!"
echo " [+] Localhost URL:      http://127.0.0.1:${APEX_PORT}/"
echo " [+] Examiner Console:   http://127.0.0.1:${APEX_PORT}/evaluator"
echo " [+] Swagger API Docs:   http://127.0.0.1:${APEX_PORT}/docs"
echo " [+] Server Log File:    lab.log"
echo "=============================================================================="
echo ""

echo "[*] Opening browser..."
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:${APEX_PORT}/" >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
    open "http://127.0.0.1:${APEX_PORT}/" >/dev/null 2>&1 &
elif command -v gio >/dev/null 2>&1; then
    gio open "http://127.0.0.1:${APEX_PORT}/" >/dev/null 2>&1 &
else
    echo "[!] No GUI browser opener detected. Please open http://127.0.0.1:${APEX_PORT}/ in your browser."
fi

echo ""
echo "NOTE: KEEP THIS TERMINAL OPEN while using the lab."
echo "Press Ctrl+C at any time to stop the APEX Cyber Range."
echo ""

# Keep running in foreground
wait "$SERVER_PID"

