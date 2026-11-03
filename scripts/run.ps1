# run.ps1 - start the gateway on Windows, bringing up a demo database if one is
# reachable. Requires PostgreSQL 16+ binaries on PATH (initdb, pg_ctl, psql).
#
#   .\scripts\run.ps1
#   .\scripts\run.ps1 -Http -Port 8411
#   .\scripts\run.ps1 -Config C:\sources.json -NoDemo

param(
    [switch]$Http,
    [int]$Port = 8411,
    [string]$Config = "demo-sources.json",
    [switch]$NoDemo
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Bin = Join-Path $Root "target\debug\pg-guardrails.exe"

if (-not (Test-Path $Bin)) {
    Write-Host "building..."
    cargo build
}

if (-not (Test-Path $Config)) {
    Write-Host "no registry at $Config; copying the demo registry"
    Copy-Item (Join-Path $Root "demo-sources.json") $Config
}

if (-not $NoDemo) {
    $listening = (Get-NetTCPConnection -LocalPort 5433 -State Listen -ErrorAction SilentlyContinue)
    if (-not $listening) {
        Write-Host "no PostgreSQL on 5433. Start one, or pass -NoDemo with your own -Config."
        Write-Host "  initdb -D demo-db -U demo --auth=trust"
        Write-Host "  pg_ctl -D demo-db start"
        exit 1
    }
}

$listeningPort = (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
if ($Http -and $listeningPort) {
    Write-Host "port $Port is already in use. Choose another."
    exit 1
}

if ($Http) {
    Write-Host "gateway: http://127.0.0.1:$Port/mcp"
    & $Bin http --config $Config --port $Port
} else {
    Write-Host "gateway: stdio. Point your MCP client at: $Bin serve --config $Config"
    & $Bin serve --config $Config
}
