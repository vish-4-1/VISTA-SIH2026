$ErrorActionPreference = "Stop"

$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCommand) {
    $dockerPath = $dockerCommand.Source
} else {
    $dockerPath = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe"
    if (-not (Test-Path $dockerPath)) {
        throw "Docker Desktop CLI was not found. Add docker.exe to PATH or install Docker Desktop."
    }
}

$gatewayRule = "if ! command -v iptables >/dev/null 2>&1; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables; fi; if ! iptables -t nat -C POSTROUTING -s 172.20.0.2/32 -d 172.22.0.10/32 -o eth1 -j SNAT --to-source 172.22.0.2 2>/dev/null; then iptables -t nat -A POSTROUTING -s 172.20.0.2/32 -d 172.22.0.10/32 -o eth1 -j SNAT --to-source 172.22.0.2; fi; iptables -t nat -L POSTROUTING -nv"

& $dockerPath exec vista-gateway sh -lc $gatewayRule
if ($LASTEXITCODE -ne 0) {
    throw "Failed to apply the VISTA gateway IPsec NAT rule. Confirm vista-gateway is running and privileged."
}