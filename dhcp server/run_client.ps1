param(
    [string]$Mac = "aa:bb:cc:dd:ee:10"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python .\dhcp_client.py --host 127.0.0.1 --mac $Mac -v
