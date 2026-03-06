"""
Configuration loader for Cyber-Guardian

Supports YAML config files with environment variable substitution.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict

import yaml


class Config:
    """Configuration manager with environment variable substitution"""

    def __init__(self, config_path: str | Path = "config.yaml"):
        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, "r") as f:
            raw_config = f.read()

        # Substitute environment variables
        substituted = self._substitute_env_vars(raw_config)
        self._config = yaml.safe_load(substituted)

    def _substitute_env_vars(self, text: str) -> str:
        """Replace ${VAR_NAME} with environment variable values"""
        pattern = re.compile(r'\$\{([^}]+)\}')

        def replacer(match):
            var_name = match.group(1)
            value = os.getenv(var_name)
            if value is None:
                raise ValueError(f"Environment variable not set: {var_name}")
            return value

        return pattern.sub(replacer, text)

    def get(self, path: str, default: Any = None) -> Any:
        """
        Get config value by dot-notation path

        Example:
            config.get("redteam.reporting.formats")
        """
        parts = path.split(".")
        value = self._config

        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default

        return value

    def __getitem__(self, key: str) -> Any:
        """Dictionary-style access"""
        return self._config[key]

    def __contains__(self, key: str) -> bool:
        """Support 'in' operator"""
        return key in self._config

    @property
    def redteam(self) -> Dict[str, Any]:
        """Red team configuration"""
        return self._config.get("redteam", {})

    @property
    def blueteam(self) -> Dict[str, Any]:
        """Blue team configuration"""
        return self._config.get("blueteam", {})

    @property
    def target(self) -> Dict[str, Any]:
        """Target system configuration"""
        return self._config.get("target", {})

    @property
    def database(self) -> Dict[str, Any]:
        """Database configuration"""
        return self._config.get("database", {})
