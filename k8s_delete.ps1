# Kubernetes Teardown Script
Write-Host "Tearing down ThreatPulse Kubernetes resources..." -ForegroundColor Yellow
kubectl delete -f k8s/
Write-Host "[✓] Teardown complete." -ForegroundColor Green
