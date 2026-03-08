@echo off
echo Starting Backend Server...
cd phase-3
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause


