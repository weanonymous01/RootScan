# RootScan Windows Installation Script (PowerShell)
Write-Host "==> RootScan v1.0 Installer for Windows <==" -ForegroundColor Cyan

# 1. Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[!] Python was not found in PATH. Please install Python 3.11+." -ForegroundColor Red
    Exit 1
}

# 2. Virtual Environment
if (-not (Test-Path "venv")) {
    Write-Host "[*] Creating virtual environment in .\venv..." -ForegroundColor Yellow
    python -m venv venv
}

# 3. Install requirements
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
.\venv\Scripts\pip install --upgrade pip
.\venv\Scripts\pip install -r requirements.txt

# 4. Copy .env if not exists
if (-not (Test-Path ".env")) {
    Write-Host "[*] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
}

# 5. Initialize DB
Write-Host "[*] Initializing SQLite database..." -ForegroundColor Yellow
.\venv\Scripts\python -c "from app.core.configuration import get_config; from app.database.repository import DatabaseRepository; config = get_config(); db = DatabaseRepository(config.database_path); print('Database initialized at:', config.database_path)"

# 6. Automatic Tool Binary Setup
Write-Host "[*] Checking and downloading security scanner binaries into .\bin..." -ForegroundColor Yellow
.\venv\Scripts\python -c "from app.core.tool_installer import check_and_install_missing_tools; check_and_install_missing_tools(auto_download=True)"

Write-Host "`n[✓] RootScan installation complete! Run .\start.ps1 to launch." -ForegroundColor Green


