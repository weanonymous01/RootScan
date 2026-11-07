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
        "rustscan": {
            "binary": "rustscan",
            "url": "https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz",
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

            if url.endswith(".tar.gz") or url.endswith(".tgz"):
                import tarfile
                with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if member.name.endswith(tool_info["binary"]) or member.name == tool_info["binary"]:
                            f_obj = tar.extractfile(member)
                            if f_obj:
                                with open(dest_binary, "wb") as f:
                                    f.write(f_obj.read())
                                if os_name != "windows":
                                    dest_binary.chmod(0o755)
                                return True
            else:
                z = zipfile.ZipFile(io.BytesIO(resp.content))
                for member in z.namelist():
                    if member.endswith(tool_info["binary"]) or member == tool_info["binary"]:
                        data = z.read(member)
                        with open(dest_binary, "wb") as f:
                            f.write(data)
                        if os_name != "windows":
                            dest_binary.chmod(0o755)
                        return True
    except Exception:
        return False

    return False


def check_and_install_missing_tools(auto_download: bool = True, verbose: bool = False) -> Dict[str, bool]:
    """Check tool availability, download missing standalone binaries, and report status."""
    ensure_bin_in_path()
    os_name = "windows" if sys.platform.startswith("win") else ("linux" if sys.platform.startswith("linux") else "darwin")

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
        console.print(f"[bold cyan][~][/bold cyan] Checking tool dependencies... [yellow]{len(missing)} tools not in PATH/bin[/yellow]")
        if auto_download:
            console.print(f"[bold cyan][~][/bold cyan] Automatically downloading security tools to [cyan]bin/[/cyan]...")
            for t in missing:
                with console.status(f"[bold cyan]Fetching {t}..."):
                    ok = download_tool(t, os_name=os_name)
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
        console.print(f"[bold green][+][/bold green] [bold white]Active Engines Ready:[/bold white] [bold cyan]{ready_names}[/bold cyan]")
        console.print(f"[bold green][+][/bold green] [bold white]AI Security Engine :[/bold white] [bold cyan]NVIDIA NIM (nvidia/nemotron-3.5-lightning-30b-a3b)[/bold cyan]\n")

    return status
