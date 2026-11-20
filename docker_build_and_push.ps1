# ============================================================
# Build & Push ThreatPulse SOC Platform to Docker Hub
# Repository: jainishhhh/mongodb_final
# ============================================================

$ErrorActionPreference = "Stop"

$IMAGE_NAME = "jainishhhh/mongodb_final"
$TAG_LATEST = "latest"
$TAG_VERSION = "v1.0.0"

$FULL_TAG_LATEST = "${IMAGE_NAME}:${TAG_LATEST}"
$FULL_TAG_VERSION = "${IMAGE_NAME}:${TAG_VERSION}"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   ThreatPulse SOC Docker Build & Push Pipeline              " -ForegroundColor Green
Write-Host "   Target: $FULL_TAG_LATEST                                 " -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Verify Docker daemon is running
Write-Host "`n[1/4] Checking Docker daemon status..." -ForegroundColor Cyan
try {
    docker info | Out-Null
    Write-Host "[✓] Docker is running." -ForegroundColor Green
} catch {
    Write-Host "[X] Docker is not running! Please open Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

# 2. Build the Docker image
Write-Host "`n[2/4] Building Docker image ($FULL_TAG_LATEST)..." -ForegroundColor Cyan
docker build -t "$FULL_TAG_LATEST" -t "$FULL_TAG_VERSION" -f Dockerfile .
if ($LASTEXITCODE -ne 0) {
    Write-Host "[X] Docker build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "[✓] Docker image built successfully." -ForegroundColor Green

# 3. Docker Hub Login
Write-Host "`n[3/4] Checking Docker Hub authentication..." -ForegroundColor Cyan
Write-Host "If prompted, enter your Docker Hub credentials (Username: jainishhhh):" -ForegroundColor Yellow
docker login

# 4. Push images to Docker Hub
Write-Host "`n[4/4] Pushing images to Docker Hub..." -ForegroundColor Cyan
docker push "$FULL_TAG_LATEST"
docker push "$FULL_TAG_VERSION"

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " [✓] SUCCESS! Image pushed to Docker Hub:                   " -ForegroundColor Green
Write-Host "     https://hub.docker.com/r/$IMAGE_NAME                   " -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Green
