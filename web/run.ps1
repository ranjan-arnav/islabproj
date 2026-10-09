$ErrorActionPreference = 'Stop'
$WebRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $WebRoot

if (-not (Test-Path -LiteralPath '.venv')) {
    python -m venv .venv
}

& '.\.venv\Scripts\python.exe' -m pip install -r requirements.txt
& '.\.venv\Scripts\python.exe' app.py
