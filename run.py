import subprocess
import time
import sys
import os
import socket
from pathlib import Path

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def run_app():
    print("\n" + "="*50)
    print("🚀 NGFW UNIFIED PLATFORM BOOTSTRAPPER")
    print("="*50 + "\n")
    
    # 1. Port Checks
    backend_port = 8000
    frontend_port = 5173
    
    if is_port_in_use(backend_port):
        print(f"⚠️  Warning: Port {backend_port} is already in use. The Backend might fail to start.")
    if is_port_in_use(frontend_port):
        print(f"⚠️  Note: Port {frontend_port} is already in use. Assuming Frontend is already running.")
        start_frontend = False
    else:
        start_frontend = True

    processes = []

    try:
        # A. Start FastAPI Backend
        print(f"📡 Starting FastAPI Security Backend (Port {backend_port})...")
        backend_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "phase-3.backend.main:app", "--port", str(backend_port)],
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
        processes.append(("Backend", backend_proc))

        # B. Start NGFW Pipeline (Simulated capture - no Admin required)
        print("🛡️ Starting NGFW Packet Pipeline (Simulated Mode)...")
        pipeline_proc = subprocess.Popen(
            [sys.executable, "main.py", "--test"],  # Added --test flag
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
        processes.append(("Pipeline", pipeline_proc))

        # C. Start Frontend (only if port is free)
        if start_frontend:
            print(f"💻 Starting Frontend Dashboard (Port {frontend_port})...")
            frontend_dir = Path("ngfw-dashboard")
            frontend_proc = subprocess.Popen(
                ["npm.cmd" if os.name == 'nt' else "npm", "run", "dev"],
                cwd=frontend_dir,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            )
            processes.append(("Frontend", frontend_proc))
        else:
            print("⏭️ Skipping Frontend startup (already running).")

        print("\n✅ ALL SYSTEMS INITIALIZED")
        print(f"🔗 Dashboard: http://localhost:{frontend_port}")
        print(f"🔗 API Docs:  http://localhost:{backend_port}/docs")
        print("\nLogs are streaming above. Press Ctrl+C to stop all components.\n")

        # Monitor loop
        while True:
            for name, proc in processes:
                status = proc.poll()
                if status is not None:
                    print(f"\n❌ CRITICAL: {name} process exited unexpectedly with code {status}.")
                    raise KeyboardInterrupt
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n🛑 SHUTTING DOWN...")
        for name, proc in processes:
            print(f"Stopping {name}...")
            if os.name == 'nt':
                # Graceful-ish shutdown for Windows process groups
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(proc.pid)], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                proc.terminate()
        print("\n✨ All systems stopped. Have a secure day!\n")

if __name__ == "__main__":
    run_app()
















