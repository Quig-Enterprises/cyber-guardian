"""Configuration loader."""
import os
from pathlib import Path
import yaml

DEFAULT_CONFIG = Path(__file__).parent.parent / "config.yaml"


def load_config(path: str | Path | None = None) -> dict:
    config_path = Path(path) if path else DEFAULT_CONFIG
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with open(config_path) as f:
        config = yaml.safe_load(f)
    # Override DB password from env
    config["database"]["password"] = os.environ.get(
        "EQMON_AUTH_DB_PASS", os.environ.get("DB_PASS", "")
    )
    return config
