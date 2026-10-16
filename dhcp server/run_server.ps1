$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "Starting DHCP lab server (UDP lab port from config/dhcp.json)..."
python .\dhcp_server.py --host 127.0.0.1 -v
