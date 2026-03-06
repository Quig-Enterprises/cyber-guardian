"""YAML configuration loader with environment variable interpolation."""

import os
import re
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _interpolate_env_vars(value: Any) -> Any:
    """Recursively interpolate ${ENV_VAR} and $ENV_VAR patterns in strings."""
    if isinstance(value, str):
        def replace_match(m):
            var_name = m.group(1)
            result = os.environ.get(var_name, m.group(0))
            if result == m.group(0):
                logger.warning(f"Environment variable not set: {var_name}")
            return result
        return _ENV_VAR_PATTERN.sub(replace_match, value)
    elif isinstance(value, dict):
        return {k: _interpolate_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_interpolate_env_vars(item) for item in value]
    return value


def load_config(config_path: str = "config.yaml") -> dict:
    """Load YAML config file with environment variable interpolation.

    Args:
        config_path: Path to the YAML config file.

    Returns:
        Parsed and interpolated configuration dictionary.

    Raises:
        FileNotFoundError: If config file does not exist.
        yaml.YAMLError: If the YAML is malformed.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with path.open("r") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        return {}

    config = _interpolate_env_vars(raw)
    logger.debug(f"Loaded config from {config_path}")
    return config
