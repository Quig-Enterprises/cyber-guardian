"""Blue Team Configuration Provider

Provides actual system configuration files to Red Team for verification.
This ensures definitive answers rather than "maybe vulnerable" based on probing.

Architecture:
- Blue team reads actual config files from filesystem
- Red team queries blue team API for configs
- Red team gets DEFINITIVE answer about vulnerability
"""

import os
import glob
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class ConfigProvider:
    """Provides access to actual system configuration files."""

    def __init__(self):
        """Initialize config provider with known config locations."""
        self.config_paths = {
            "nginx": {
                "main": "/etc/nginx/nginx.conf",
                "sites_enabled": "/etc/nginx/sites-enabled/*.conf",
                "sites_available": "/etc/nginx/sites-available/*.conf",
                "snippets": "/etc/nginx/snippets/*.conf",
                "conf_d": "/etc/nginx/conf.d/*.conf",
            },
            "php": {
                "ini": "/etc/php/*/fpm/php.ini",
                "pool_d": "/etc/php/*/fpm/pool.d/*.conf",
            },
            "apache": {
                "main": "/etc/apache2/apache2.conf",
                "sites_enabled": "/etc/apache2/sites-enabled/*.conf",
                "mods_enabled": "/etc/apache2/mods-enabled/*.conf",
            }
        }

    def get_nginx_config(self) -> Optional[str]:
        """Read and combine all nginx configuration files.

        Returns:
            Combined nginx configuration or None if not found
        """
        configs = []

        # Main config
        if os.path.exists(self.config_paths["nginx"]["main"]):
            try:
                with open(self.config_paths["nginx"]["main"], 'r') as f:
                    configs.append(f"# From: {self.config_paths['nginx']['main']}\n")
                    configs.append(f.read())
            except Exception as e:
                logger.error(f"Error reading nginx main config: {e}")

        # Sites enabled
        for pattern in ["sites_enabled", "sites_available", "snippets", "conf_d"]:
            for conf_file in glob.glob(self.config_paths["nginx"][pattern]):
                try:
                    with open(conf_file, 'r') as f:
                        configs.append(f"\n# From: {conf_file}\n")
                        configs.append(f.read())
                except Exception as e:
                    logger.error(f"Error reading {conf_file}: {e}")

        if configs:
            return "\n".join(configs)
        return None

    def get_php_config(self) -> Optional[str]:
        """Read PHP configuration files.

        Returns:
            Combined PHP configuration or None if not found
        """
        configs = []

        for pattern in ["ini", "pool_d"]:
            for conf_file in glob.glob(self.config_paths["php"][pattern]):
                try:
                    with open(conf_file, 'r') as f:
                        configs.append(f"\n# From: {conf_file}\n")
                        configs.append(f.read())
                except Exception as e:
                    logger.error(f"Error reading {conf_file}: {e}")

        if configs:
            return "\n".join(configs)
        return None

    def get_apache_config(self) -> Optional[str]:
        """Read Apache configuration files.

        Returns:
            Combined Apache configuration or None if not found
        """
        configs = []

        if os.path.exists(self.config_paths["apache"]["main"]):
            try:
                with open(self.config_paths["apache"]["main"], 'r') as f:
                    configs.append(f"# From: {self.config_paths['apache']['main']}\n")
                    configs.append(f.read())
            except Exception as e:
                logger.error(f"Error reading apache main config: {e}")

        for pattern in ["sites_enabled", "mods_enabled"]:
            for conf_file in glob.glob(self.config_paths["apache"][pattern]):
                try:
                    with open(conf_file, 'r') as f:
                        configs.append(f"\n# From: {conf_file}\n")
                        configs.append(f.read())
                except Exception as e:
                    logger.error(f"Error reading {conf_file}: {e}")

        if configs:
            return "\n".join(configs)
        return None

    def get_config(self, software: str) -> Optional[str]:
        """Get configuration for specified software.

        Args:
            software: Software name (nginx, php, apache)

        Returns:
            Configuration content or None
        """
        if software.lower() == "nginx":
            return self.get_nginx_config()
        elif software.lower() == "php":
            return self.get_php_config()
        elif software.lower() == "apache":
            return self.get_apache_config()
        else:
            logger.warning(f"Unknown software: {software}")
            return None


# Singleton instance
_provider = None


def get_provider() -> ConfigProvider:
    """Get the singleton config provider instance."""
    global _provider
    if _provider is None:
        _provider = ConfigProvider()
    return _provider


if __name__ == "__main__":
    # Test the provider
    provider = get_provider()

    print("Testing ConfigProvider...")
    print("=" * 70)

    nginx_config = provider.get_nginx_config()
    if nginx_config:
        print(f"\n✓ Nginx config found ({len(nginx_config)} bytes)")
        print("\nFirst 500 characters:")
        print(nginx_config[:500])
    else:
        print("\n✗ Nginx config not found")

    php_config = provider.get_php_config()
    if php_config:
        print(f"\n✓ PHP config found ({len(php_config)} bytes)")
    else:
        print("\n✗ PHP config not found")
