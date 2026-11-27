#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

if [ -d "$DIR/TraceX3" ]; then
    cd "$DIR/TraceX3"
fi

if [ -f "$DIR/.venv/bin/python" ]; then
    PYTHON="$DIR/.venv/bin/python"
elif [ -f "$DIR/../.venv/bin/python" ]; then
    PYTHON="$DIR/../.venv/bin/python"
elif [ -f "venv/bin/python" ]; then
    PYTHON="venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    echo "[!] Error: Python not found."
    exit 1
fi

export PYTHONPATH=".:gateway:api_export:SIH26:$PYTHONPATH"
chmod +x run.py || true
exec "$PYTHON" run.py
