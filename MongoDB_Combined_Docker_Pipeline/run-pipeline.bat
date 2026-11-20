@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo MongoDB combined pipeline: Chapter 7 dashboard -> Chapter 8 -> Chapter 9
echo ============================================================
echo.
echo NOTE: this bundle uses combined-mongo1/2/3 container names to avoid
echo colliding with the older standalone Chapter 9 containers.
echo.

docker compose up -d --build mongo1 mongo2 mongo3 dashboard
if errorlevel 1 goto :failed

echo.
echo [1/6] Initialize MongoDB replica set
docker compose --profile tools run --rm lab9 setup
if errorlevel 1 goto :failed

echo.
echo [2/6] Chapter 8.1 - Replica set and replication
docker compose --profile tools run --rm lab8 /work/Activity_8.1/lab_8_1_replica_set.py
if errorlevel 1 goto :failed

echo.
echo [3/6] Chapter 8.2 - Failover monitor
docker compose --profile tools run --rm lab8 /work/Activity_8.2/lab_8_2_failover_monitor.py
if errorlevel 1 goto :failed

echo.
echo [4/6] Chapter 9.1 - Write concern latency
docker compose --profile tools run --rm lab9 9.1
if errorlevel 1 goto :failed

echo.
echo [5/6] Chapter 9.1 Try It Yourself - journal latency
docker compose --profile tools run --rm lab9 9.1-try
if errorlevel 1 goto :failed

echo.
echo [6/6] Chapter 9.2 - Network partition
docker compose --profile tools run --rm lab9 9.2
if errorlevel 1 goto :failed

echo.
echo ============================================================
echo PIPELINE COMPLETED
echo Dashboard: http://localhost:8080
echo Chapter 8 JSON results are saved next to their Python scripts.
echo Chapter 9 results are in chapter9\output\
echo ============================================================
pause
exit /b 0

:failed
echo.
echo PIPELINE STOPPED because a command failed. Read the error above.
echo Dashboard may still be available at http://localhost:8080
pause
exit /b 1
