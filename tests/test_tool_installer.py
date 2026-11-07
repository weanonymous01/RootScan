"""Unit tests for automated tool installer and dependency resolver."""

from __future__ import annotations

import os
from pathlib import Path
import unittest

from app.core.tool_installer import (
    BIN_DIR,
    PROJECT_ROOT,
    TOOL_RELEASES,
    ensure_bin_in_path,
    get_current_os_and_arch,
    extract_binary_from_archive,
)


class TestToolInstaller(unittest.TestCase):
    """Test suite for tool installer module."""

    def test_bin_directory_and_path(self):
        ensure_bin_in_path()
        self.assertTrue(BIN_DIR.exists())
        self.assertIn(str(BIN_DIR), os.environ.get("PATH", ""))

    def test_os_and_arch_detection(self):
        os_name, arch = get_current_os_and_arch()
        self.assertIn(os_name, ("windows", "linux", "darwin"))
        self.assertIn(arch, ("amd64", "arm64"))

    def test_tool_releases_schema(self):
        for (os_name, arch), tools in TOOL_RELEASES.items():
            self.assertIn(os_name, ("windows", "linux", "darwin"))
            self.assertIn(arch, ("amd64", "arm64"))
            for tool_name, meta in tools.items():
                self.assertIn("binary", meta)
                self.assertIn("url", meta)
                self.assertTrue(meta["url"].startswith("https://github.com/"))

    def test_check_tools_status(self):
        from app.core.tool_installer import check_and_install_missing_tools
        status = check_and_install_missing_tools(auto_download=False, verbose=True)
        self.assertIsInstance(status, dict)


if __name__ == "__main__":
    unittest.main()
