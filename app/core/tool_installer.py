"""Automated tool dependency checker and downloader for RootScan."""

from __future__ import annotations

import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
from typing import Dict, List, Optional, Tuple
import zipfile

import httpx
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BIN_DIR = PROJECT_ROOT / "bin"

# Verified release URLs across OS & CPU architectures
TOOL_RELEASES = {
    ("windows", "amd64"): {
        "httpx": {
            "binary": "httpx.exe",
            "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_windows_amd64.zip",
        },
        "nuclei": {
            "binary": "nuclei.exe",
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_windows_amd64.zip",
        },
        "rustscan": {
            "binary": "rustscan.exe",
            "url": "https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-windows-rustscan.exe.zip",
        },
        "naabu": {
            "binary": "naabu.exe",
            "url": "https://github.com/projectdiscovery/naabu/releases/download/v2.7.0/naabu_2.7.0_windows_amd64.zip",
        },
    },
    ("linux", "amd64"): {
        "httpx": {
            "binary": "httpx",
            "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip",
        },
        "nuclei": {
            "binary": "nuclei",
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip",
        },
        "naabu": {
            "binary": "naabu",
            "url": "https://github.com/projectdiscovery/naabu/releases/download/v2.7.0/naabu_2.7.0_linux_amd64.zip",
        },
        "rustscan": {
            "binary": "rustscan",
            "url": "https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz.zip",
        },
    },
    ("linux", "arm64"): {
        "httpx": {
            "binary": "httpx",
            "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_arm64.zip",
        },
        "nuclei": {
            "binary": "nuclei",
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_arm64.zip",
        },
        "naabu": {
            "binary": "naabu",
            "url": "https://github.com/projectdiscovery/naabu/releases/download/v2.7.0/naabu_2.7.0_linux_arm64.zip",
        },
        "rustscan": {
            "binary": "rustscan",
            "url": "https://github.com/bee-san/RustScan/releases/download/2.4.1/aarch64-linux-rustscan.zip",
        },
    },
    ("darwin", "amd64"): {
        "httpx": {
            "binary": "httpx",
            "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_macOS_amd64.zip",
        },
        "nuclei": {
            "binary": "nuclei",
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_macOS_amd64.zip",
        },
        "naabu": {
            "binary": "naabu",
            "url": "https://github.com/projectdiscovery/naabu/releases/download/v2.7.0/naabu_2.7.0_macOS_amd64.zip",
        },
        "rustscan": {
            "binary": "rustscan",
            "url": "https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-macos-rustscan.tar.gz.zip",
        },
    },
    ("darwin", "arm64"): {
        "httpx": {
            "binary": "httpx",
            "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_macOS_arm64.zip",
        },
        "nuclei": {
            "binary": "nuclei",
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_macOS_arm64.zip",
        },
        "naabu": {
            "binary": "naabu",
            "url": "https://github.com/projectdiscovery/naabu/releases/download/v2.7.0/naabu_2.7.0_macOS_arm64.zip",
        },
        "rustscan": {
            "binary": "rustscan",
            "url": "https://github.com/bee-san/RustScan/releases/download/2.4.1/aarch64-macos-rustscan.tar.gz.zip",
        },
    },
}


def get_current_os_and_arch() -> Tuple[str, str]:
    """Detect current operating system and processor architecture."""
    if sys.platform.startswith("win"):
        os_name = "windows"
    elif sys.platform.startswith("linux"):
        os_name = "linux"
    elif sys.platform.startswith("darwin"):
        os_name = "darwin"
    else:
        os_name = "linux"

    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    return os_name, arch


def ensure_bin_in_path():
    """Ensure project bin/ directory exists and sits at the front of os.environ['PATH']."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    bin_str = str(BIN_DIR)
    current_parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    filtered = [p for p in current_parts if os.path.normcase(os.path.normpath(p)) != os.path.normcase(os.path.normpath(bin_str))]
    os.environ["PATH"] = os.pathsep.join([bin_str, *filtered])


def extract_binary_from_archive(data: bytes, binary_name: str) -> Optional[bytes]:
    """Recursively search and extract the target binary from a zip or tar archive."""
    # Check if zip
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for member in z.namelist():
                    if member.endswith(binary_name) or member == binary_name:
                        return z.read(member)
                    elif member.endswith(".tar.gz") or member.endswith(".tgz"):
                        sub_extracted = extract_binary_from_archive(z.read(member), binary_name)
                        if sub_extracted:
                            return sub_extracted
        except Exception:
            pass

    # Check if tar
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            for member in tar.getmembers():
                if member.name.endswith(binary_name) or member.name == binary_name:
                    f = tar.extractfile(member)
                    if f:
                        return f.read()
    except Exception:
        pass

    return None


def download_tool(tool_name: str, os_name: Optional[str] = None, arch: Optional[str] = None) -> bool:
    """Download and extract a standalone tool binary into project bin/."""
    ensure_bin_in_path()
    det_os, det_arch = get_current_os_and_arch()
    os_name = os_name or det_os
    arch = arch or det_arch

    key = (os_name, arch)
    if key not in TOOL_RELEASES:
        key = (os_name, "amd64")

    os_tools = TOOL_RELEASES.get(key, {})
    tool_info = os_tools.get(tool_name)
    if not tool_info:
        return False

    url = tool_info["url"]
    dest_binary = BIN_DIR / tool_info["binary"]

    try:
        with httpx.Client(follow_redirects=True, timeout=60.0) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return False

            raw_binary = extract_binary_from_archive(resp.content, tool_info["binary"])
            if raw_binary:
                with open(dest_binary, "wb") as f:
                    f.write(raw_binary)
                if os_name != "windows":
                    dest_binary.chmod(0o755)
                return True
    except Exception:
        return False

    return False


def check_and_install_missing_tools(auto_download: bool = True, verbose: bool = False) -> Dict[str, bool]:
    """Check tool availability, download missing standalone binaries, and report status."""
    ensure_bin_in_path()
    os_name, arch = get_current_os_and_arch()

    tools_to_check = ["rustscan", "httpx", "nuclei", "naabu"]
    missing = []
    ready = []
    for t in tools_to_check:
        bin_file = BIN_DIR / (f"{t}.exe" if os_name == "windows" else t)
        if shutil.which(t) is not None or bin_file.exists():
            ready.append(t)
        else:
            missing.append(t)

    status: Dict[str, bool] = {t: True for t in ready}

    if missing:
        console.print(f"[bold cyan][~][/bold cyan] OS detected: [bold cyan]{os_name.title()} ({arch})[/bold cyan] - checking tool dependencies...")
        console.print(f"[bold yellow][*][/bold yellow] Missing security scanner binaries: [yellow]{', '.join(missing)}[/yellow]")
        if auto_download:
            console.print(f"[bold cyan][~][/bold cyan] Automatically downloading security tools to [cyan]bin/[/cyan]...")
            for t in missing:
                with console.status(f"[bold cyan]Fetching {t} for {os_name}/{arch}..."):
                    ok = download_tool(t, os_name=os_name, arch=arch)
                if ok:
                    console.print(f"  [bold green][+][/bold green] {t:<10} : [bold green]DOWNLOADED & READY[/bold green]")
                    status[t] = True
                    ready.append(t)
                else:
                    console.print(f"  [bold yellow][*][/bold yellow] {t:<10} : [dim]Using internal Python engine fallback[/dim]")
                    status[t] = False
        console.print()
    elif verbose:
        ready_names = ", ".join(t.capitalize() for t in ready)
        console.print(f"[bold green][+][/bold green] [bold white]Active Engines Ready:[/bold white] [bold cyan]{ready_names}[/bold cyan] [dim]({os_name.title()} {arch})[/dim]")
        console.print(f"[bold green][+][/bold green] [bold white]AI Security Engine :[/bold white] [bold cyan]NVIDIA NIM (nvidia/nemotron-3.5-lightning-30b-a3b)[/bold cyan]\n")

    return status
