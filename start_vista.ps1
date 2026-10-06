# VISTA Testbed & AI Engine Launcher
# Smart India Hackathon 2026 · NTRO

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  VISTA: AI-Powered IPsec VPN Protocol Analyzer & SOC" -ForegroundColor Green
Write-Host "  SIH26160 · National Technical Research Organisation (NTRO)" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

$VENV_PYTHON = "c:\vista\vista-ml\.venv\Scripts\python.exe"

if (-not (Test-Path $VENV_PYTHON)) {
    Write-Host "[!] Virtual environment not found at $VENV_PYTHON" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Launching VISTA FastAPI Backend Server on port 8000..." -ForegroundColor Cyan
Start-Process -FilePath $VENV_PYTHON -ArgumentList "run_backend.py --port 8000" -WorkingDirectory "c:\vista"

Write-Host "[*] Launching VISTA Vite Dashboard on port 5173..." -ForegroundColor Cyan
Start-Process -FilePath "npm.cmd" -ArgumentList "run dev" -WorkingDirectory "c:\vista\vista-dashboard"

Write-Host ""
Write-Host "[+] VISTA Stack Successfully Started!" -ForegroundColor Green
Write-Host "    - Dashboard UI: http://localhost:5173" -ForegroundColor White
Write-Host "    - API Docs:     http://localhost:8000/docs" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
