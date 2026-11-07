# Developer & Contributor Guide

Thank you for contributing to RootScan! This document outlines coding standards, environment setup, and the testing workflow.

---

## 1. Development Environment Setup

RootScan requires Python 3.11+.

```bash
# Clone the repository
git clone https://github.com/USERNAME/RootScan.git
cd RootScan

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux / macOS
# Or on Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Install core and development dependencies
pip install -r requirements.txt
```

---

## 2. Running Automated Tests

RootScan uses `pytest` and `pytest-asyncio`:

```bash
# Run the entire test suite
pytest -v

# Run a specific test module
pytest tests/test_validation.py -v
pytest tests/test_fixtures.py -v
pytest tests/test_tui.py -v
```

---

## 3. Code Architecture & Style Guide

- **Type Annotations**: All function signatures must include full type hints (`from __future__ import annotations`).
- **Pydantic Validation**: All external tool outputs, target models, and report schemas must use Pydantic v2 models in `app/reports/schemas.py`.
- **Subprocess Security**: Never use `shell=True`. Always execute external commands via `TaskManager.execute_tool()`.
- **Untrusted Input**: Treat all remote server banners, HTTP headers, and target responses as untrusted strings. Never interpolate untrusted text directly into prompt templates without clear data delimitation.
- **Terminal Presentation**: Follow the **RustScan** hacker terminal design convention:
  - `[+]` Bright Green: Success, ports, completions
  - `[>]` Bright Cyan: Active execution, stages, IPs
  - `[*]` Bright Yellow: Notices, scope boundaries
  - `[-]` Bright Red: Errors, vulnerabilities

---

## 4. Git Workflow

```bash
# Create a feature branch
git checkout -b feat/your-feature-name

# Run test suite before committing
pytest -v

# Commit with conventional commit messages
git commit -m "feat(scanners): Add custom vulnerability scanner adapter"
```

