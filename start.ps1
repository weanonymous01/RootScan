# RootScan Launcher for Windows (PowerShell)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if (Test-Path "venv\Scripts\activate.ps1") {
    & ".\venv\Scripts\Activate.ps1"
}

$BinDir = Join-Path $ScriptDir "bin"
if (Test-Path $BinDir) {
    $env:PATH = "$BinDir;$env:PATH"
}

python -m app.main $args


