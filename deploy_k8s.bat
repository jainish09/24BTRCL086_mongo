@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo   ThreatPulse SOC - Kubernetes Deployment (Docker Desktop)
echo ============================================================
echo.

echo [1/3] Checking Kubernetes cluster connection...
kubectl cluster-info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Cannot connect to Kubernetes! Ensure Kubernetes is enabled in Docker Desktop.
    echo.
    pause
    exit /b 1
)
echo [OK] Kubernetes cluster is reachable.
echo.

echo [2/3] Applying Kubernetes manifests (Namespace, Secret, ConfigMap, Deployment, Service)...
kubectl apply -f k8s/

echo.
echo [3/3] Waiting for deployment rollout...
kubectl rollout status deployment/threatpulse-soc-app -n threatpulse --timeout=120s

echo.
echo ============================================================
echo  [SUCCESS] ThreatPulse SOC is LIVE in Kubernetes!
echo ============================================================
echo  Access URL:   http://localhost:8080
echo  NodePort:     http://localhost:30080
echo.
echo Active Pods:
kubectl get pods -n threatpulse
echo.
echo Services:
kubectl get svc -n threatpulse
echo.
pause
