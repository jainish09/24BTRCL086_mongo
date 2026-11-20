@echo off
echo ========================================================
echo ThreatPulse - Chapter 13 Kubernetes StatefulSet Deploy
echo ========================================================

where kubectl >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] kubectl is not installed or not in PATH.
    echo Please install k3s, minikube, or kind to deploy to Kubernetes.
    exit /b 1
)

echo Applying mongodb-statefulset.yaml to cluster...
kubectl apply -f "%~dp0mongodb-statefulset.yaml"

echo Waiting for pods (mongo-0, mongo-1, mongo-2)...
kubectl rollout status statefulset/mongo --timeout=120s

echo Verifying pod status:
kubectl get pods -l app=mongodb -o wide

echo StatefulSet deployment complete. Data is persisted on PVCs.
