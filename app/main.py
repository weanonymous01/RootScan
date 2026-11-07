"""RootScan application entrypoint."""

from __future__ import annotations

import sys


def main():
    """Main application launcher: dispatches to TUI or CLI based on arguments."""
    if len(sys.argv) > 1 and sys.argv[1] not in ("--tui", "-t"):
        # Run CLI mode
        from app.cli import run_cli
        run_cli()
    else:
        # Launch full-screen interactive Textual TUI
        from app.tui.app import RootScanApp
        app = RootScanApp()
        app.run()


if __name__ == "__main__":
    main()

