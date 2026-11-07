"""RootScan application entrypoint."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

# Auto-reexec inside project virtual environment if invoked via global python
base_dir = Path(__file__).resolve().parent.parent
venv_py_win = base_dir / "venv" / "Scripts" / "python.exe"
venv_py_nix = base_dir / "venv" / "bin" / "python3"
venv_py = venv_py_win if venv_py_win.exists() else (venv_py_nix if venv_py_nix.exists() else None)

if venv_py and sys.executable.lower() != str(venv_py).lower():
    result = subprocess.run([str(venv_py), "-m", "app.main"] + sys.argv[1:])
    sys.exit(result.returncode)


def main():
    """Main application launcher: dispatches to RustScan CLI by default, or TUI if requested."""
    if "--tui" in sys.argv or "-t" in sys.argv:
        # Launch full-screen interactive Textual TUI
        from app.tui.app import RootScanApp
        app = RootScanApp()
        app.run()
    else:
        # Run authentic RustScan CLI mode
        from app.cli import run_cli
        run_cli()


if __name__ == "__main__":
    main()
