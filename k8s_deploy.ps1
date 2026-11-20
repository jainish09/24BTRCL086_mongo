# ============================================================
# Kubernetes Deployment for Docker Desktop
# Namespace: threatpulse
# Application: threatpulse-soc-app
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Deploying ThreatPulse SOC to Kubernetes (Docker Desktop) " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Verify kubectl is connected
Write-Host "`n[1/3] Checking Kubernetes cluster connection..." -ForegroundColor Cyan
try {
    kubectl cluster-info | Out-Null
    Write-Host "[✓] Kubernetes cluster is ready." -ForegroundColor Green
} catch {
    Write-Host "[X] Cannot connect to Kubernetes! Ensure Kubernetes is enabled in Docker Desktop Settings -> Kubernetes." -ForegroundColor Red
    exit 1
}

# 2. Apply Manifests
Write-Host "`n[2/3] Applying Kubernetes manifests (Namespace, Secret, ConfigMap, Deployment, Service)..." -ForegroundColor Cyan
kubectl apply -f k8s/

# 3. Wait for Rollout
Write-Host "`n[3/3] Waiting for deployment rollout..." -ForegroundColor Cyan
kubectl rollout status deployment/threatpulse-soc-app -n threatpulse --timeout=120s

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " [✓] ThreatPulse SOC is LIVE in Kubernetes!                 " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Access URL:      http://localhost:8080                      " -ForegroundColor Cyan
Write-Host "Alt NodePort:    http://localhost:30080                     " -ForegroundColor Cyan
Write-Host "`nActive Pods:" -ForegroundColor Yellow
kubectl get pods -n threatpulse
Write-Host "`nServices:" -ForegroundColor Yellow
kubectl get svc -n threatpulse
