"""RootScan application entrypoint."""

from __future__ import annotations

import sys


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
