# RootScan Launcher for Windows (PowerShell)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if (Test-Path "venv\Scripts\activate.ps1") {
    & ".\venv\Scripts\Activate.ps1"
}

python -m app.main $args

