# ============================================================
# Git Push Script for ThreatPulse SOC
# Remote: https://github.com/jainish09/24BTRCL086_mongo.git
# ============================================================

$ErrorActionPreference = "Stop"

$REPO_URL = "https://github.com/jainish09/24BTRCL086_mongo.git"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Pushing ThreatPulse SOC to GitHub (Private Repo)         " -ForegroundColor Green
Write-Host "   Target: $REPO_URL                                        " -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Initialize Git if not initialized
if (-not (Test-Path ".git")) {
    Write-Host "`n[1/5] Initializing Git repository..." -ForegroundColor Cyan
    git init
} else {
    Write-Host "`n[1/5] Git repository already initialized." -ForegroundColor Green
}

# 2. Configure Remote
Write-Host "`n[2/5] Setting remote origin to $REPO_URL..." -ForegroundColor Cyan
try { git remote remove origin | Out-Null } catch {}
git remote add origin $REPO_URL
git branch -M main

# 3. Stage Files
Write-Host "`n[3/5] Staging files (Labs 7-18, Docker, Kubernetes manifests)..." -ForegroundColor Cyan
git add .

# 4. Commit
Write-Host "`n[4/5] Committing changes..." -ForegroundColor Cyan
git commit -m "feat: complete ThreatPulse SOC Platform, Labs 7-18, Docker, Kubernetes & Threat Advisor"

# 5. Push
Write-Host "`n[5/5] Pushing to GitHub (main)..." -ForegroundColor Cyan
Write-Host "If prompted, authenticate in browser or enter GitHub Personal Access Token:" -ForegroundColor Yellow
git push -u origin main --force

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " [✓] SUCCESS! Pushed to https://github.com/jainish09/24BTRCL086_mongo" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
