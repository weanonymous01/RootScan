# RootScan Installation & Setup Guide

This guide provides instructions for installing and running **RootScan** on supported operating systems.

---

## 1. Prerequisites

- **Python 3.11+** (Verify with `python3 --version` or `python --version`)
- **Git**
- **NVIDIA NIM API Key** (Free tier available at [build.nvidia.com](https://build.nvidia.com))

---

## 2. Automated Installation

### Linux (Kali Linux, Ubuntu, Debian)

RootScan provides an automated installation script that detects your distribution, installs required system packages, creates a virtual environment, and initialises the SQLite database.

```bash
# 1. Clone the repository
git clone https://github.com/USERNAME/RootScan.git
cd RootScan

# 2. Grant execution permissions
chmod +x install.sh start.sh

# 3. Run the installer
./install.sh

# 4. Launch RootScan
./start.sh
```

### Windows (PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/USERNAME/RootScan.git
cd RootScan

# 2. Run the PowerShell installer
.\install.ps1

# 3. Launch RootScan
.\start.ps1
```

---

## 3. Security Scanners Setup

RootScan orchestrates multiple external cybersecurity tools. Tools missing from your system are safely bypassed without crashing the assessment.

To install the complete toolchain:

### Debian / Ubuntu / Kali Linux:
```bash
# Standard Network & Web Tools
sudo apt update
sudo apt install -y nmap whatweb nikto curl

# ProjectDiscovery Go Tools (Nuclei, httpx, naabu, dnsx)
# Requires Go (golang) installed
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# RustScan (Fast port scanner)
# Via cargo:
cargo install rustscan
```

---

## 4. Configuring the AI Security Analyst (NVIDIA NIM)

1. Open or create the `.env` file in the repository root:
```bash
cp .env.example .env
```

2. Add your NVIDIA NIM credentials:
```env
NVIDIA_NIM_API_KEY=nvapi-your-key-here
NVIDIA_NIM_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b
NVIDIA_NIM_BASE_URL=https://integrate.api.nvidia.com/v1
```

3. Test your connection:
```bash
python -m app.main ai-test
```
You should see:
`[+] Connected successfully to NVIDIA NIM (nvidia/nemotron-3.5-lightning-30b-a3b).`

---

## 5. Verification & Health Check

Verify your installation by listing registered security scanners:
```bash
python -m app.main tools
```
Run an assessment test against an authorized target:
```bash
python -m app.main scan scanme.nmap.org --profile quick
```
