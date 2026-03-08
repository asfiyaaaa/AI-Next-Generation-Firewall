@echo off
echo Starting Backend Server on port 8000...
cd /d "%~dp0phase-3"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
pause


