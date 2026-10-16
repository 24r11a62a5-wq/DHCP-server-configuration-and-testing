$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python -m unittest discover -s tests -v
