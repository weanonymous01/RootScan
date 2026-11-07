# RootScan Launcher for Windows (PowerShell)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$BinDir = Join-Path $ScriptDir "bin"
if (Test-Path $BinDir) {
    $env:PATH = "$BinDir;$env:PATH"
}

if (Test-Path "venv\Scripts\activate.ps1") {
    & ".\venv\Scripts\Activate.ps1"
}

python -m app.main $args


