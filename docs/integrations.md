# Security Tool Integration & Adapter Guide

RootScan implements a decoupled **Adapter Pattern** for all external security scanners. The orchestrator never contains tool-specific parsing or command-line syntax; each tool maintains its own lifecycle adapter.

---

## 1. Scanner Adapter Lifecycle

Every scanner adapter inherits from `BaseScannerAdapter` located in [`app/scanners/base.py`](file:///c:/Users/adars/Downloads/RootScan/app/scanners/base.py):

```python
from app.scanners.base import BaseScannerAdapter
from app.reports.schemas import NormalizedFinding

class CustomScannerAdapter(BaseScannerAdapter):
    @property
    def name(self) -> str:
        return "CustomTool"

    @property
    def binary_name(self) -> str:
        return "customtool"

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        # Formulate safe argument array without shell=True
        return [self.binary_name, "-t", target, "-o", str(output_path)]

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        # Transform tool-native output into normalized findings
        findings = []
        # ... parse output ...
        return findings
```

---

## 2. Mandatory Adapter Responsibilities

1. **Path Availability (`is_available`)**:  
   Uses `shutil.which` to verify binary presence in the host's system `$PATH`. If not found, the orchestrator records a skipped stage and continues without failure.

2. **Safe Execution Array (`build_command`)**:  
   Commands must be constructed as a list of strings (`["nmap", "-sV", target]`) passed directly to `asyncio.create_subprocess_exec`. **Never concatenate strings or use `shell=True`**.

3. **Evidence Preservation**:  
   Raw stdout, stderr, XML, or JSON output must be preserved in `data/scans/<SCN-ID>/evidence/` for auditability and transparency.

4. **Normalized Output Schema (`parse_output`)**:  
   Outputs must map directly to RootScan's unified Pydantic schemas:
   - `PortResult`
   - `ServiceResult`
   - `NormalizedFinding` (Title, Severity, Confidence, CVE, Evidence, Remediation)

---

## 3. Registering a Tool in `config/tools.toml`

Add tool metadata to [`config/tools.toml`](file:///c:/Users/adars/Downloads/RootScan/config/tools.toml):

```toml
[tools.customtool]
name = "CustomTool"
binary = "customtool"
purpose = "Vulnerability assessment"
category = "vulnerability"
version_args = ["--version"]
min_version = "1.0.0"
timeout_seconds = 300
is_primary = false
```

