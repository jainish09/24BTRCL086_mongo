@echo off
REM ============================================================================
REM MongoDB Chapter 12: Security Lab One-Click Runner
REM Generates certs, launches docker-compose, and executes verification scripts
REM ============================================================================
setlocal enabledelayedexpansion

cd /d "%~dp0"
echo ============================================================================
echo   Chapter 12: MongoDB Database Security Automation
echo ============================================================================

echo.
echo [Step 1/3] Generating TLS Certificates (CA, Server, Client, SANs)...
python generate_certs.py
if %ERRORLEVEL% neq 0 (
    echo [-] Error generating certificates. Exiting.
    exit /b %ERRORLEVEL%
)

echo.
echo [Step 2/3] Starting Docker Compose container (chapter12-mongo-security)...
docker compose up -d mongo-sec
if %ERRORLEVEL% neq 0 (
    echo [-] Error launching docker-compose. Exiting.
    exit /b %ERRORLEVEL%
)

echo.
echo Waiting 5 seconds for MongoDB TLS service to become ready...
timeout /t 5 /nobreak >nul

echo.
echo [Step 3/3] Executing Chapter 12 Test Pipeline...
python run_all_tests.py
if %ERRORLEVEL% neq 0 (
    echo [-] Security tests encountered errors.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================================
echo [SUCCESS] Chapter 12 Security Lab Completed Successfully!
echo ============================================================================
pause
