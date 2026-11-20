@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo   Pushing ThreatPulse SOC to GitHub
echo   Target: https://github.com/jainish09/24BTRCL086_mongo.git
echo ============================================================
echo.

echo [1/5] Checking Git repository initialization...
if not exist ".git" (
    git init
    echo [OK] Initialized new Git repository.
)

echo.
echo [2/5] Configuring remote origin...
git remote remove origin >nul 2>&1
git remote add origin https://github.com/jainish09/24BTRCL086_mongo.git
git branch -M main

echo.
echo [3/5] Staging all files (Labs 7-18, Docker, Kubernetes, Readme)...
git add .

echo.
echo [4/5] Creating commit...
git commit -m "feat: complete ThreatPulse SOC Platform, Labs 7-18, Docker, Kubernetes & Threat Advisor"

echo.
echo [5/5] Pushing to GitHub (main branch)...
echo If prompted, sign in to your GitHub account:
git push -u origin main --force

echo.
echo ============================================================
echo  [SUCCESS] Repository successfully pushed to GitHub!
echo  View at: https://github.com/jainish09/24BTRCL086_mongo
echo ============================================================
echo.
pause
