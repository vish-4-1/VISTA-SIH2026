# VISTA Automated Headless UI Screenshot Capture Tool
# Uses Microsoft Edge Headless to capture pixel-perfect 1920x1080 screenshots of all 8 SOC views.

$ErrorActionPreference = "Stop"

$edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path $edgePath)) {
    throw "Microsoft Edge executable not found at: $edgePath"
}

$screenshotDir = "C:\vista\docs\screenshots"
if (-not (Test-Path $screenshotDir)) {
    New-Item -ItemType Directory -Path $screenshotDir -Force | Out-Null
}

$views = @(
    @{ tab = "overview"; file = "01_overview.png"; name = "Security Overview" },
    @{ tab = "traffic";  file = "02_traffic_analysis.png"; name = "Traffic Intelligence" },
    @{ tab = "ai";       file = "03_ai_analysis.png"; name = "AI Intelligence & Dual-ML" },
    @{ tab = "security"; file = "04_security_assessment.png"; name = "Security Posture Assessment" },
    @{ tab = "threat";   file = "05_threat_intelligence.png"; name = "Threat Intelligence" },
    @{ tab = "testbed";  file = "06_testbed_3d.png"; name = "3D Interactive Testbed" },
    @{ tab = "reports";  file = "07_reports.png"; name = "Compliance Reports" },
    @{ tab = "dataset";  file = "08_dataset_hub.png"; name = "Dataset Studio" }
)

Write-Host "=== Capturing 8 VISTA SOC UI Screenshots (1920x1080) ===" -ForegroundColor Cyan

foreach ($v in $views) {
    $targetPath = Join-Path $screenshotDir $v.file
    $url = "http://127.0.0.1:5173/?tab=$($v.tab)"
    
    # Remove existing file so Edge writes a fresh capture
    if (Test-Path $targetPath) {
        Remove-Item -Path $targetPath -Force
    }

    $tmpDir = Join-Path $env:TEMP ("edge_shot_" + [System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        Write-Host "Capturing $($v.name) ($($v.tab)) -> $($v.file)..." -NoNewline
        $edgeArgs = @(
            "--headless=new",
            "--no-first-run",
            "--disable-background-networking",
            "--user-data-dir=$tmpDir",
            "--window-size=1920,1080",
            "--virtual-time-budget=6000",
            "--screenshot=$targetPath",
            $url
        )

        $proc = Start-Process -FilePath $edgePath -ArgumentList $edgeArgs -NoNewWindow -PassThru -Wait
        
        if (Test-Path $targetPath) {
            $len = (Get-Item $targetPath).Length
            Write-Host " OK ($([Math]::Round($len / 1024, 1)) KB)" -ForegroundColor Green
        } else {
            Write-Host " FAILED (Target file was not generated)" -ForegroundColor Red
        }
    } finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nAll captures complete:" -ForegroundColor Cyan
Get-ChildItem $screenshotDir\*.png | Select-Object Name, Length, LastWriteTime
