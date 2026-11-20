@echo off
setlocal
cd /d "%~dp0MongoDB_Combined_Docker_Pipeline\lab7\backend"

echo ============================================================
echo   ThreatPulse - Cyber Threat Intelligence SOC Platform
echo ============================================================
echo.

REM Stop stale Docker dashboard container if running to avoid port 8080 conflict
docker stop combined-dashboard >nul 2>&1

echo Starting ThreatPulse SOC Platform on http://localhost:8080 ...
echo [INFO] Backend is live with auto-reload at http://localhost:8080
echo.

start http://localhost:8080
python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload
pause

