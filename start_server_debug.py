#!/usr/bin/env python
"""Debug script to start the backend server and show all output."""
import sys
import os
from pathlib import Path

# Change to phase-3 directory
os.chdir(Path(__file__).parent / "phase-3")

print("=" * 60)
print("Starting Backend Server...")
print("=" * 60)
print(f"Working directory: {os.getcwd()}")
print(f"Python: {sys.executable}")
print("=" * 60)

try:
    import uvicorn
    print("✅ Uvicorn imported successfully")
    
    # Start the server
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info"
    )
except Exception as e:
    print(f"❌ Error starting server: {e}")
    import traceback
    traceback.print_exc()
    input("Press Enter to exit...")


