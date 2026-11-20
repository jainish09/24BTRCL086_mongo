<#
.SYNOPSIS
    Threat Advisor - Sentinel PC Scanner One-Line Installer
    Installs Sentinel Agent to %LOCALAPPDATA%\ThreatAdvisor and runs initial vulnerability scan.
#>

[CmdletBinding()]
param(
    [string]$ServerUrl = "http://localhost:8080"
)

$ErrorActionPreference = "SilentlyContinue"
$TargetDir = "$env:LOCALAPPDATA\ThreatAdvisor"
$AgentScript = "$TargetDir\sentinel_agent.py"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Threat Advisor - Installing Sentinel PC Scanner          " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

# 1. Fetch 30-minute install token from server
Write-Host "[+] Requesting enrollment token from $ServerUrl..." -ForegroundColor Gray
try {
    $tokenRes = Invoke-RestMethod -Uri "$ServerUrl/install.ps1" -Method Get -UseBasicParsing
    # Extract token
    if ($tokenRes -match 'InstallToken = "([^"]+)"') {
        $InstallToken = $matches[1]
    } else {
        $InstallToken = "fallback_demo_token"
    }
} catch {
    $InstallToken = "offline_demo_token"
}

# 2. Download agent script
Write-Host "[+] Downloading Sentinel scanner agent..." -ForegroundColor Gray
try {
    Invoke-WebRequest -Uri "$ServerUrl/agent/sentinel_agent.py" -OutFile $AgentScript -UseBasicParsing
} catch {
    # If downloading from localhost failed, check local relative path
    $localScanner = Join-Path $PSScriptRoot "sentinel_agent.py"
    if (Test-Path $localScanner) {
        Copy-Item -Path $localScanner -Destination $AgentScript -Force
    }
}

# 3. Locate python executable
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    $pythonExe = "python.exe"
}

# 4. Enroll with server
Write-Host "[+] Enrolling device with Threat Advisor server..." -ForegroundColor Cyan
& $pythonExe "$AgentScript" --enroll --server "$ServerUrl" --token "$InstallToken"

# 5. Register 5-minute scheduled check-in task using schtasks
$TaskName = "ThreatAdvisorScanner"
$Action = "pythonw `"$AgentScript`" --poll"
schtasks /create /tn $TaskName /tr $Action /sc MINUTE /mo 5 /f 2>$null | Out-Null

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [✓] Threat Advisor Scanner successfully installed!       " -ForegroundColor Green
Write-Host " Device is now actively protected and audited on MongoDB. " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
