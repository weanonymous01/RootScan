"""Automated tool dependency checker and downloader for RootScan."""

from __future__ import annotations

import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import Dict, List, Optional
import zipfile

import httpx
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BIN_DIR = PROJECT_ROOT / "bin"

TOOL_RELEASES = {
    "windows": {
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
    "linux": {
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
    },
}


def ensure_bin_in_path():
    """Ensure project bin/ directory exists and is prepended to os.environ['PATH']."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    bin_str = str(BIN_DIR)
    current_path = os.environ.get("PATH", "")
    if bin_str not in current_path.split(os.pathsep):
        os.environ["PATH"] = bin_str + os.pathsep + current_path


def download_tool(tool_name: str, os_name: str = "windows") -> bool:
    """Download and extract a standalone tool binary into project bin/."""
    ensure_bin_in_path()
    os_tools = TOOL_RELEASES.get(os_name, {})
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

            z = zipfile.ZipFile(io.BytesIO(resp.content))
            for member in z.namelist():
                if member.endswith(tool_info["binary"]) or member == tool_info["binary"]:
                    data = z.read(member)
                    with open(dest_binary, "wb") as f:
                        f.write(data)
                    if os_name != "windows":
                        dest_binary.chmod(0o755)
                    return True
    except Exception as e:
        return False

    return False


def check_and_install_missing_tools(auto_download: bool = True) -> Dict[str, bool]:
    """Check tool availability and automatically download any missing standalone binaries."""
    ensure_bin_in_path()
    os_name = "windows" if sys.platform.startswith("win") else ("linux" if sys.platform.startswith("linux") else "darwin")

    tools_to_check = ["httpx", "nuclei", "rustscan", "naabu"]
    missing = []
    for t in tools_to_check:
        # Check if available in PATH or inside bin/
        bin_file = BIN_DIR / (f"{t}.exe" if os_name == "windows" else t)
        if shutil.which(t) is None and not bin_file.exists():
            missing.append(t)

    status: Dict[str, bool] = {}
    if not missing:
        return status

    console.print(f"[bold cyan][~][/bold cyan] Checking tool dependencies... [yellow]{len(missing)} tools not in PATH[/yellow]")
    if auto_download:
        console.print(f"[bold cyan][~][/bold cyan] Automatically downloading security tools to [cyan]bin/[/cyan]...")
        for t in missing:
            with console.status(f"[bold cyan]Fetching {t}..."):
                ok = download_tool(t, os_name=os_name)
            if ok:
                console.print(f"  [bold green][+][/bold green] {t:<10} : [bold green]DOWNLOADED & READY[/bold green]")
                status[t] = True
            else:
                console.print(f"  [bold yellow][*][/bold yellow] {t:<10} : [dim]Using internal Python engine fallback[/dim]")
                status[t] = False

    # Check Nmap
    if shutil.which("nmap") is None:
        if os_name == "windows":
            console.print("  [bold yellow][*][/bold yellow] nmap       : [dim]Optional: install via 'winget install Insecure.Nmap'[/dim]")
        else:
            console.print("  [bold yellow][*][/bold yellow] nmap       : [dim]Optional: install via 'sudo apt install nmap'[/dim]")

    console.print()
    return status
