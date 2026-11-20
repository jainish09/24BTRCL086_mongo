@echo off
setlocal
cd /d "%~dp0"
docker compose down
echo.
echo Stopped combined pipeline containers. Named MongoDB volumes are kept.
pause
