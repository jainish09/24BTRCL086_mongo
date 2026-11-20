@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo   ThreatPulse SOC - Docker Build and Push to Docker Hub
echo   Target: jainishhhh/mongodb_final
echo ============================================================
echo.

echo [1/4] Checking Docker daemon status...
docker info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker is not running! Please open Docker Desktop and try again.
    echo.
    pause
    exit /b 1
)
echo [OK] Docker daemon is running.
echo.

echo [2/4] Building Docker image (jainishhhh/mongodb_final:latest)...
docker build -t jainishhhh/mongodb_final:latest -t jainishhhh/mongodb_final:v1.0.0 -f Dockerfile .
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker build failed!
    echo.
    pause
    exit /b 1
)
echo [OK] Docker image built successfully.
echo.

echo [3/4] Docker Hub Login...
echo If prompted, enter your Docker Hub password:
docker login -u jainishhhh

echo.
echo [4/4] Pushing images to Docker Hub...
docker push jainishhhh/mongodb_final:latest
docker push jainishhhh/mongodb_final:v1.0.0

echo.
echo ============================================================
echo  [SUCCESS] All images pushed to Docker Hub!
echo  View your repository at:
echo  https://hub.docker.com/r/jainishhhh/mongodb_final
echo ============================================================
echo.
pause
