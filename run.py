#!/usr/bin/env python3
"""
run.py — Local development and hosting runner for TraceX Platform.
Starts the FastAPI Gateway server on http://localhost:8000 with auto-reload.
"""
import os
import sys
import socket
import subprocess

def find_uvicorn():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "..", ".venv", "bin", "uvicorn"),
        os.path.join(base_dir, ".venv", "bin", "uvicorn"),
        os.path.join(base_dir, "venv", "bin", "uvicorn"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return [c]
    return [sys.executable, "-m", "uvicorn"]

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(base_dir)

    pythonpath = [
        base_dir,
        os.path.join(base_dir, "gateway"),
        os.path.join(base_dir, "api_export"),
        os.path.join(base_dir, "SIH26")
    ]
    env = os.environ.copy()
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(pythonpath + ([existing_pp] if existing_pp else []))

    port = int(env.get("PORT", 8000))
    host = env.get("HOST", "0.0.0.0")

    print("\n" + "=" * 72)
    print("  🛡️  TraceX Cyber-Forensic Threat Defense Platform (Local Host)")
    print("=" * 72)
    print(f"  • Local Website:       http://localhost:{port}/")
    print(f"  • Login Portal:        http://localhost:{port}/login")
    print(f"  • Direct Logout:       http://localhost:{port}/logout")
    print(f"  • Swagger API Docs:    http://localhost:{port}/docs")
    print(f"  • Chrome Extension:    TraceX3/extension (Load unpacked in chrome://extensions)")
    print("=" * 72)

    if is_port_in_use(port):
        print(f"[!] Warning: Port {port} is already in use by another process.")
        print(f"    You can access the existing instance at http://localhost:{port}/")
        return

    cmd = find_uvicorn() + [
        "gateway.main:app",
        "--host", host,
        "--port", str(port),
        "--reload"
    ]
    print(f"[*] Starting local server with: {' '.join(cmd)}\n")

    try:
        subprocess.run(cmd, env=env)
    except KeyboardInterrupt:
        print("\n[!] Shutting down TraceX Local Host...")

if __name__ == "__main__":
    main()
