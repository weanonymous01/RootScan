# RootScan

> **Scan. Discover. Understand.**  
> *One terminal. Multiple tools. One automated pipeline. One intelligent security analyst.*

---

## 1. Overview

**RootScan** is an open-source, locally executed, AI-powered automated security assessment toolkit. It orchestrates reconnaissance, network port scanning, service enumeration, and vulnerability discovery into a unified, transparent terminal experience.

RootScan automatically:
1. Validates targets and strictly enforces authorization scope boundaries (protecting against SSRF and private IP leakage).
2. Gathers DNS and network intelligence (RDAP, ASN, reverse DNS).
3. Discovers open ports and running services using industry-standard tools (Nmap, RustScan, httpx, WhatWeb).
4. Executes non-destructive vulnerability assessments (Nuclei).
5. Normalizes and deduplicates findings into structured schemas with preserved evidence.
6. Generates persistent reports identified by unique scan IDs (`SCN-YYYYMMDD-XXXXX`).
7. Leverages **NVIDIA NIM** to provide an evidence-grounded AI Security Analyst that explains findings, reviews exploit intelligence, constructs potential attack paths, and delivers prioritized remediation guidance.

---

## 2. Installation & Quick Start

### Linux (Kali, Ubuntu, Debian)

```bash
git clone https://github.com/USERNAME/RootScan.git
cd RootScan
chmod +x install.sh start.sh
./install.sh
./start.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/USERNAME/RootScan.git
cd RootScan
.\install.ps1
.\start.ps1
```

---

## 3. NVIDIA NIM AI Setup

RootScan uses the NVIDIA NIM API for local-first, privacy-respecting AI security analysis.

1. Sign up and obtain an API key from [build.nvidia.com](https://build.nvidia.com).
2. Create or edit your `.env` file:

```env
NVIDIA_NIM_API_KEY=nvapi-your-key-here
NVIDIA_NIM_MODEL=meta/llama-3.3-70b-instruct
NVIDIA_NIM_BASE_URL=https://integrate.api.nvidia.com/v1
```

*Note: RootScan operates seamlessly for standard scanning and report generation even if the AI key is not configured.*

---

## 4. Usage

### Interactive Terminal User Interface (TUI)

Launch the full-screen dashboard:
```bash
./start.sh
```
Keybindings:
- `Tab` / `Shift+Tab`: Navigate form controls
- `Arrow Keys`: Navigate lists and tables
- `Enter`: Select action
- `Escape`: Return to previous view
- `Q`: Quit

### Headless CLI Mode

RootScan can be invoked directly from scripts or CI/CD pipelines:

```bash
# Execute standard assessment against a domain
python -m app.main scan scanme.nmap.org --profile standard

# Execute internal assessment (requires explicit authorization flag)
python -m app.main scan 192.168.1.10 --profile quick --allow-private

# View historical scan records
python -m app.main history

# Inspect security tool health and versions
python -m app.main tools

# Verify NVIDIA NIM connection
python -m app.main ai-test
```

---

## 5. Security & Scope Guardrails

- **Subprocess Isolation**: External binaries are executed via fixed argument lists using `asyncio.create_subprocess_exec` without `shell=True`.
- **Anti-SSRF & Scope Enforcement**: Automatic blocking of loopback addresses (`127.0.0.1`, `::1`), link-local metadata endpoints (`169.254.169.254`), and private networks unless explicitly confirmed.
- **Prompt Injection Defense**: All scanner outputs and web banners are treated as untrusted data strings when passed to the LLM.
- **Non-Destructive Scanning**: Default workflows execute passive and probe-based checks only; exploit payloads are never launched.

---

## 6. Project Architecture

```text
RootScan/
├── config/
│   ├── settings.toml        # Core application settings
│   ├── tools.toml           # Security tool registry configuration
│   └── profiles.toml        # Assessment profiles (quick, standard, deep)
├── app/
│   ├── core/                # Orchestrator, event bus, scope manager, task manager
│   ├── security/            # Target validation, anti-SSRF, scope guardrails
│   ├── scanners/            # Nmap, Nuclei, httpx tool adapters
│   ├── parsers/             # XML, JSONL, JSON output parsers
│   ├── database/            # SQLite repository and schemas
│   ├── reports/             # Report generator, schemas, persistent storage
│   ├── intelligence/        # DNS and IP RDAP intelligence
│   ├── ai/                  # NVIDIA NIM client and prompt pipelines
│   └── tui/                 # Textual full-screen terminal interface
├── data/
│   ├── database/            # SQLite WAL database (rootscan.db)
│   └── scans/               # Persistent reports and evidence per scan ID
├── tests/                   # Automated unit & integration test suite
├── install.sh / start.sh    # Linux installation and launcher scripts
└── install.ps1 / start.ps1  # Windows installation and launcher scripts
```

---

## 7. License

Distributed under the [MIT License](LICENSE).

