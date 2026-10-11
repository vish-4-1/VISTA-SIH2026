param(
    [int]$BackendPort = 8000,
    [int]$DashboardPort = 5173,
    [switch]$Visible
)

$ErrorActionPreference = 'Stop'
$RepoRoot = $PSScriptRoot
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$DashboardDir = Join-Path $RepoRoot 'vista-dashboard'

function Test-HttpReady([string]$Url) {
    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 2 -UseBasicParsing
        return ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500)
    } catch {
        return $false
    }
}

function Test-PortInUse([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        return $task.AsyncWaitHandle.WaitOne(400) -and $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Python environment not found: $Python. Create the root .venv and install backend requirements first."
}
if (-not (Test-Path -LiteralPath (Join-Path $DashboardDir 'node_modules'))) {
    throw "Dashboard dependencies not found at $DashboardDir\node_modules. Run npm install in vista-dashboard first."
}
$Npm = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
if (-not $Npm) { throw 'npm.cmd was not found on PATH. Install Node.js/npm and retry.' }

$services = @(
    @{ Name = 'Backend'; Port = $BackendPort; Url = "http://127.0.0.1:$BackendPort/" },
    @{ Name = 'Dashboard'; Port = $DashboardPort; Url = "http://127.0.0.1:$DashboardPort/" }
)
foreach ($service in $services) {
    if (Test-PortInUse $service.Port) {
        if (Test-HttpReady $service.Url) {
            throw "$($service.Name) port $($service.Port) already serves $($service.Url). Reuse that service or stop it explicitly before starting VISTA."
        }
        throw "Port $($service.Port) is already occupied by an unverified process. No process was stopped; choose another port or resolve it explicitly."
    }
}

$windowStyle = if ($Visible) { 'Normal' } else { 'Hidden' }
$backendArgs = "run_backend.py --port $BackendPort"
$dashboardArgs = "run dev -- --host 127.0.0.1 --port $DashboardPort --strictPort"

Write-Host "Starting VISTA backend on port $BackendPort..."
$backend = Start-Process -FilePath $Python -ArgumentList $backendArgs -WorkingDirectory $RepoRoot -PassThru -WindowStyle $windowStyle
Write-Host "Starting VISTA dashboard on port $DashboardPort..."
$dashboard = Start-Process -FilePath $Npm -ArgumentList $dashboardArgs -WorkingDirectory $DashboardDir -PassThru -WindowStyle $windowStyle

$deadline = (Get-Date).AddSeconds(40)
$ready = @{ Backend = $false; Dashboard = $false }
while ((Get-Date) -lt $deadline -and (-not $ready.Backend -or -not $ready.Dashboard)) {
    if (-not $ready.Backend) { $ready.Backend = Test-HttpReady $services[0].Url }
    if (-not $ready.Dashboard) { $ready.Dashboard = Test-HttpReady $services[1].Url }
    Start-Sleep -Milliseconds 500
}

if (-not $ready.Backend -or -not $ready.Dashboard) {
    $details = @()
    if (-not $ready.Backend) { $details += "Backend not ready (PID $($backend.Id), port $BackendPort)" }
    if (-not $ready.Dashboard) { $details += "Dashboard not ready (PID $($dashboard.Id), port $DashboardPort)" }
    throw "Startup health check failed: $($details -join '; '). Processes were left running for inspection; no unrelated process was stopped."
}

Write-Host "VISTA is ready: http://127.0.0.1:$DashboardPort (backend http://127.0.0.1:$BackendPort/docs)"
Write-Host "Process IDs: backend=$($backend.Id), dashboard=$($dashboard.Id). Stop only these processes when finished."
