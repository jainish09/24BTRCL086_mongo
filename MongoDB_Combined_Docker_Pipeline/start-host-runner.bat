@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo Starting ThreatPulse Host Lab Runner on port 8001...
echo ============================================================
echo.
python host_runner.py
pause
