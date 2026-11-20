@echo off
setlocal
cd /d "%~dp0"

echo ============================================================================
echo Chapter 11: MongoDB Sharding Labs (11.1 and 11.2)
echo ============================================================================
echo.
echo Starting Chapter 11 Sharded Cluster (cfg1, shard1, shard2, mongos)...
docker compose up -d cfg1 shard1 shard2 mongos
if errorlevel 1 goto :failed

echo.
echo Waiting 8 seconds for MongoDB services to initialize...
timeout /t 8 /nobreak >nul

echo.
echo Running Chapter 11 Python Pipeline...
python run_lab11.py
if errorlevel 1 goto :failed

echo.
echo ============================================================================
echo CHAPTER 11 LABS COMPLETED SUCCESSFULLY!
echo Review report in REPORT.md and metrics in distribution_summary.json
echo ============================================================================
pause
exit /b 0

:failed
echo.
echo PIPELINE FAILED. Please read the error message above.
pause
exit /b 1
