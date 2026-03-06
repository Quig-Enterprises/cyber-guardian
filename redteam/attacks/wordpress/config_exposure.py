"""WordPress configuration file exposure attacks — CRITICAL severity.

Tests for exposed configuration files that could leak database credentials,
API keys, and other secrets. Checks wp-config.php direct access, common
backup patterns, .env files, and setup-config.php accessibility.
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Patterns that indicate real configuration content is leaking
CONFIG_LEAK_PATTERNS = [
    "DB_NAME",
    "DB_PASSWORD",
    "DB_HOST",
    "DB_USER",
    "DB_CHARSET",
    "DB_COLLATE",
    "define(",
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "table_prefix",
    "$table_prefix",
    "ABSPATH",
    "WP_DEBUG",
]

ENV_LEAK_PATTERNS = [
    "DB_PASSWORD",
    "DB_HOST",
    "DB_DATABASE",
    "DATABASE_URL",
    "APP_KEY",
    "APP_SECRET",
    "AWS_ACCESS_KEY",
    "AWS_SECRET",
    "MAIL_PASSWORD",
    "REDIS_PASSWORD",
    "API_KEY",
    "SECRET_KEY",
]


class ConfigExposureAttack(Attack):
    """Test for exposed WordPress configuration files leaking credentials."""

    name = "wordpress.config_exposure"
    category = "wordpress"
    severity = Severity.CRITICAL
    description = "Exposed configuration files leaking database credentials and secrets"
    target_types = {"wordpress"}

    WP_CONFIG_BACKUP_PATHS = [
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/wp-config.php.old",
        "/wp-config.php.orig",
        "/wp-config.php.save",
        "/wp-config.txt",
        "/.wp-config.php.swp",
    ]

    async def execute(self, client) -> list[AttackResult]:
        results = []

        results.append(await self._test_wp_config_direct(client))
        results.extend(await self._test_wp_config_backups(client))
        results.append(await self._test_env_file(client))
        results.append(await self._test_setup_config(client))
        results.append(await self._test_wp_config_sample(client))

        return results

    async def _test_wp_config_direct(self, client) -> AttackResult:
        """GET /wp-config.php — should return 403/404, never PHP source."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/wp-config.php", cookies={})
            duration = (time.monotonic() - start) * 1000

            leaked = [p for p in CONFIG_LEAK_PATTERNS if p in body]

            if leaked:
                return self._make_result(
                    variant="wp_config_direct",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f"wp-config.php returned PHP source with {len(leaked)} credential patterns: {leaked[:5]}",
                    details=(
                        f"Direct access to /wp-config.php returned HTTP {status} with "
                        f"configuration content. Matched patterns: {', '.join(leaked[:5])}. "
                        f"This exposes database credentials and authentication salts."
                    ),
                    request={"method": "GET", "path": "/wp-config.php"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="wp_config_direct",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no config patterns found",
                details=f"Direct access to /wp-config.php returned HTTP {status} with no credential leakage.",
                request={"method": "GET", "path": "/wp-config.php"},
                response={"status": status, "body": body[:200]},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="wp_config_direct",
                status=Status.ERROR,
                details=f"Error testing wp-config.php: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_wp_config_backups(self, client) -> list[AttackResult]:
        """Try common backup file patterns for wp-config.php."""
        results = []

        for path in self.WP_CONFIG_BACKUP_PATHS:
            start = time.monotonic()
            try:
                status, body, headers = await client.get(path, cookies={})
                duration = (time.monotonic() - start) * 1000

                leaked = [p for p in CONFIG_LEAK_PATTERNS if p in body]

                if status == 200 and leaked:
                    results.append(self._make_result(
                        variant="wp_config_backup",
                        status=Status.VULNERABLE,
                        severity=Severity.CRITICAL,
                        evidence=f"Backup file {path} exposes config: {leaked[:5]}",
                        details=(
                            f"Backup file {path} returned HTTP {status} with "
                            f"{len(leaked)} credential patterns. "
                            f"Matched: {', '.join(leaked[:5])}. "
                            f"Backup files bypass PHP execution and expose raw source."
                        ),
                        request={"method": "GET", "path": path},
                        response={"status": status, "body": body[:500]},
                        duration_ms=duration,
                    ))
                else:
                    results.append(self._make_result(
                        variant="wp_config_backup",
                        status=Status.DEFENDED,
                        evidence=f"{path} returned HTTP {status}, no config leak",
                        details=f"Backup path {path} returned HTTP {status} with no credential patterns.",
                        request={"method": "GET", "path": path},
                        response={"status": status},
                        duration_ms=duration,
                    ))
            except Exception as e:
                results.append(self._make_result(
                    variant="wp_config_backup",
                    status=Status.ERROR,
                    details=f"Error testing {path}: {e}",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))

        return results

    async def _test_env_file(self, client) -> AttackResult:
        """GET /.env — check for database credentials and API keys."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/.env", cookies={})
            duration = (time.monotonic() - start) * 1000

            leaked = [p for p in ENV_LEAK_PATTERNS if p in body]
            # Also check for key=value pattern typical of .env files
            has_env_format = "=" in body and len(body.strip().splitlines()) > 1

            if status == 200 and (leaked or has_env_format):
                return self._make_result(
                    variant="env_file",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f".env file accessible with {len(leaked)} credential patterns, env_format={has_env_format}",
                    details=(
                        f"/.env returned HTTP {status}. "
                        f"Found {len(leaked)} credential patterns: {', '.join(leaked[:5])}. "
                        f"Environment files typically contain database passwords and API keys."
                    ),
                    request={"method": "GET", "path": "/.env"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="env_file",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no env content found",
                details=f"/.env returned HTTP {status} with no credential leakage.",
                request={"method": "GET", "path": "/.env"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="env_file",
                status=Status.ERROR,
                details=f"Error testing .env: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_setup_config(self, client) -> AttackResult:
        """GET /wp-admin/setup-config.php — if accessible, WP can be reinstalled."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get(
                f"{client.admin_path}/setup-config.php", cookies={}
            )
            duration = (time.monotonic() - start) * 1000

            # Setup page indicators
            setup_indicators = [
                "setup-config.php",
                "wp-setup-config",
                "database name",
                "Below you should enter",
                "wp_install",
                "Let&#8217;s go",
            ]
            found = [ind for ind in setup_indicators if ind.lower() in body.lower()]

            if status == 200 and found:
                return self._make_result(
                    variant="setup_config",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f"setup-config.php accessible with indicators: {found}",
                    details=(
                        f"WordPress setup page at {client.admin_path}/setup-config.php "
                        f"is accessible (HTTP {status}). An attacker could reconfigure "
                        f"WordPress to connect to a malicious database and take over the site."
                    ),
                    request={"method": "GET", "path": f"{client.admin_path}/setup-config.php"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="setup_config",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, setup page not exposed",
                details=f"setup-config.php returned HTTP {status}, not accessible.",
                request={"method": "GET", "path": f"{client.admin_path}/setup-config.php"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="setup_config",
                status=Status.ERROR,
                details=f"Error testing setup-config.php: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_wp_config_sample(self, client) -> AttackResult:
        """GET /wp-config-sample.php — reveals default structure, sometimes custom additions."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/wp-config-sample.php", cookies={})
            duration = (time.monotonic() - start) * 1000

            leaked = [p for p in CONFIG_LEAK_PATTERNS if p in body]

            if status == 200 and leaked:
                # Check if it contains real credentials (not just sample placeholders)
                has_real_creds = any(
                    pattern in body
                    for pattern in ["localhost", "127.0.0.1", "password_here"]
                )
                # If it has more than just placeholders, it may have custom additions
                sev = Severity.HIGH if not has_real_creds else Severity.MEDIUM

                return self._make_result(
                    variant="wp_config_sample",
                    status=Status.VULNERABLE,
                    severity=sev,
                    evidence=f"wp-config-sample.php accessible with {len(leaked)} config patterns",
                    details=(
                        f"/wp-config-sample.php returned HTTP {status} with configuration "
                        f"structure visible. Patterns found: {', '.join(leaked[:5])}. "
                        f"Reveals WordPress version hints and possibly custom configuration."
                    ),
                    request={"method": "GET", "path": "/wp-config-sample.php"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="wp_config_sample",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no config patterns found",
                details=f"/wp-config-sample.php returned HTTP {status} with no configuration exposure.",
                request={"method": "GET", "path": "/wp-config-sample.php"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="wp_config_sample",
                status=Status.ERROR,
                details=f"Error testing wp-config-sample.php: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
