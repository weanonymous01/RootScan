"""Configuration management for RootScan."""

from __future__ import annotations

import os
from pathlib import Path
import tomllib
from typing import Any, Dict, Optional

from dotenv import load_dotenv


class Configuration:
    """Central configuration store for RootScan."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).resolve().parent.parent.parent
        self.config_dir = self.base_dir / "config"
        
        # Load environment variables (.env)
        env_file = self.base_dir / ".env"
        if env_file.exists():
            load_dotenv(dotenv_path=env_file)
        else:
            load_dotenv()

        # Load TOML configurations
        self.settings: Dict[str, Any] = self._load_toml(self.config_dir / "settings.toml")
        self.tools: Dict[str, Any] = self._load_toml(self.config_dir / "tools.toml")
        self.profiles: Dict[str, Any] = self._load_toml(self.config_dir / "profiles.toml")

        # Resolve paths
        self.data_dir = self.base_dir / self.settings.get("app", {}).get("data_dir", "data")
        self.database_path = self.base_dir / self.settings.get("app", {}).get("database_path", "data/database/rootscan.db")
        self.scans_dir = self.base_dir / self.settings.get("app", {}).get("scans_dir", "data/scans")
        self.bin_dir = self.base_dir / "bin"

        # Ensure primary directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self.bin_dir.mkdir(parents=True, exist_ok=True)

        # Prepend bin/ directory to PATH so local tools are immediately available
        bin_str = str(self.bin_dir)
        curr_path = os.environ.get("PATH", "")
        if bin_str not in curr_path.split(os.pathsep):
            os.environ["PATH"] = bin_str + os.pathsep + curr_path

    def _load_toml(self, file_path: Path) -> Dict[str, Any]:
        """Load and parse a TOML file safely."""
        if not file_path.exists():
            return {}
        try:
            with open(file_path, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            print(f"[!] Warning: Failed to load {file_path}: {e}")
            return {}

    # Convenience accessors
    @property
    def nvidia_nim_api_key(self) -> Optional[str]:
        return os.getenv("NVIDIA_NIM_API_KEY")

    @property
    def nvidia_nim_model(self) -> str:
        return os.getenv("NVIDIA_NIM_MODEL", self.settings.get("ai", {}).get("default_model", "meta/llama-3.3-70b-instruct"))

    @property
    def nvidia_nim_base_url(self) -> str:
        return os.getenv("NVIDIA_NIM_BASE_URL", self.settings.get("ai", {}).get("base_url", "https://integrate.api.nvidia.com/v1"))

    @property
    def allow_private_ranges(self) -> bool:
        env_val = os.getenv("ROOTSCAN_ALLOW_PRIVATE_RANGES")
        if env_val is not None:
            return env_val.lower() in ("1", "true", "yes")
        return self.settings.get("security", {}).get("allow_private_ranges_default", False)

    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Retrieve tool-specific configuration."""
        return self.tools.get("tools", {}).get(tool_name.lower(), {})

    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        """Retrieve scan profile configuration."""
        return self.profiles.get("profiles", {}).get(profile_name.lower(), {})


# Global singleton instance
_config_instance: Optional[Configuration] = None


def get_config(base_dir: Optional[Path] = None) -> Configuration:
    """Retrieve or initialize the global Configuration instance."""
    global _config_instance
    if _config_instance is None or base_dir is not None:
        _config_instance = Configuration(base_dir=base_dir)
    return _config_instance

