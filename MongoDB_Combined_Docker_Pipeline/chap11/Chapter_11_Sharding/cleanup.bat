@echo off
setlocal
cd /d "%~dp0"

echo ============================================================================
echo SAFE CLEANUP: Chapter 11 (Preserves Chapters 7-10 Data)
echo ============================================================================
echo.
echo Stopping Chapter 11 containers only (cfg1, shard1, shard2, mongos)...
docker compose down

echo.
echo Chapter 11 containers have been stopped.
echo.
set /p REMOVE_DATA="Do you also want to delete Chapter 11 volumes (chapter11-cfg1-data, chapter11-shard1-data, chapter11-shard2-data)? (y/N): "
if /i "%REMOVE_DATA%"=="y" (
    docker compose down -v
    echo Chapter 11 volumes removed. Chapters 7-10 data remains untouched.
) else (
    echo Chapter 11 volumes retained.
)

echo.
echo Done.
pause
