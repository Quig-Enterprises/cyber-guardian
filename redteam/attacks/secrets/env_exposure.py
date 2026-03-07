"""Environment file web exposure attack module.

Probes common paths where environment/configuration files are accidentally
served over HTTP. Successful retrieval of files containing secret key patterns
indicates the target is leaking credentials.

Evaluation:
- HTTP 200 with key patterns in body -> VULNERABLE
- HTTP 200 without key patterns -> PARTIAL (file accessible but may be innocuous)
- HTTP 403/404/redirect -> DEFENDED
"""

import asyncio
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Patterns that indicate a file contains real secrets
SECRET_KEY_PATTERNS = [
    "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD",
    "API_KEY", "SECRET_KEY", "APP_SECRET", "APP_KEY",
    "AWS_SECRET", "AWS_ACCESS_KEY",
    "PRIVATE_KEY", "AUTH_SECRET", "JWT_SECRET",
    "STRIPE_", "SENDGRID_", "TWILIO_",
    "REDIS_PASSWORD", "MAIL_PASSWORD",
]

PROBE_THROTTLE_S = 0.1  # 100ms between probes


class EnvExposureAttack(Attack):
    """Probe for environment and configuration files exposed over HTTP."""

    name = "secrets.env_exposure"
    category = "secrets"
    severity = Severity.CRITICAL
    description = "Probe for .env, config, and docker files accidentally served via HTTP"
    target_types = {"app", "wordpress", "generic"}

    def _body_has_secrets(self, body: str) -> bool:
        """Check if body contains known secret key names."""
        body_upper = body.upper()
        return any(pat in body_upper for pat in SECRET_KEY_PATTERNS)

    def _classify_response(self, status_code: int, body: str, variant: str) -> tuple[Status, str]:
        """Classify a probe response into a Status and evidence string."""
        if status_code == 200:
            if self._body_has_secrets(body):
                return Status.VULNERABLE, f"HTTP 200 with secret key patterns in response body ({len(body)} bytes)"
            else:
                return Status.PARTIAL, f"HTTP 200 but no obvious secret patterns detected ({len(body)} bytes)"
        elif status_code in (403, 401):
            return Status.DEFENDED, f"HTTP {status_code} — server actively blocks access"
        elif status_code == 404:
            return Status.DEFENDED, f"HTTP 404 — file not found"
        else:
            return Status.DEFENDED, f"HTTP {status_code} — not accessible"

    async def execute(self, client) -> list[AttackResult]:
        results = []
        results.append(await self._probe_dotenv(client))
        results.append(await self._probe_env_example(client))
        results.append(await self._probe_docker_env(client))
        results.append(await self._probe_config_files(client))
        return results

    async def _probe_dotenv(self, client) -> AttackResult:
        """Probe for common .env file paths."""
        start = time.monotonic()
        paths = [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.backup",
            "/.env.prod",
            "/.env.staging",
        ]

        vulnerable_path = None
        defended_count = 0
        last_status_code = None
        last_body = ""

        try:
            for path in paths:
                status_code, body, headers = await client.get(path, cookies={})
                last_status_code = status_code
                last_body = body
                status, evidence = self._classify_response(status_code, body, "dotenv")

                if status == Status.VULNERABLE:
                    vulnerable_path = path
                    duration = (time.monotonic() - start) * 1000
                    return self._make_result(
                        variant="dotenv",
                        status=Status.VULNERABLE,
                        evidence=f"{path} → {evidence}",
                        details=(
                            f"Environment file exposed at {path}. "
                            "Contains secret key patterns — credentials may be leaked."
                        ),
                        request={"path": path, "method": "GET"},
                        response={"status": status_code, "body_preview": body[:200]},
                        duration_ms=duration,
                    )
                elif status == Status.PARTIAL:
                    vulnerable_path = path  # file accessible, flag as partial
                    last_status_code = status_code
                    last_body = body
                elif status == Status.DEFENDED:
                    defended_count += 1

                await asyncio.sleep(PROBE_THROTTLE_S)

            duration = (time.monotonic() - start) * 1000

            if vulnerable_path and last_status_code == 200:
                return self._make_result(
                    variant="dotenv",
                    status=Status.PARTIAL,
                    evidence=f"{vulnerable_path} returned HTTP 200 but no obvious secret patterns",
                    details="Environment file is accessible but did not contain recognizable secret patterns. Manual review recommended.",
                    request={"path": vulnerable_path},
                    response={"status": last_status_code, "body_preview": last_body[:200]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="dotenv",
                status=Status.DEFENDED,
                evidence=f"All {len(paths)} .env paths returned non-200 responses",
                details=f"Tested paths: {', '.join(paths)}",
                request={"paths_tested": paths},
                duration_ms=duration,
            )

        except Exception as e:
            return self._make_result(
                variant="dotenv",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _probe_env_example(self, client) -> AttackResult:
        """Probe for .env.example files that may contain real values."""
        start = time.monotonic()
        paths = [
            "/.env.example",
            "/.env.sample",
            "/.env.template",
        ]

        try:
            for path in paths:
                status_code, body, headers = await client.get(path, cookies={})
                status, evidence = self._classify_response(status_code, body, "env_example")

                if status in (Status.VULNERABLE, Status.PARTIAL):
                    duration = (time.monotonic() - start) * 1000
                    result_status = Status.VULNERABLE if status == Status.VULNERABLE else Status.PARTIAL
                    return self._make_result(
                        variant="env_example",
                        status=result_status,
                        evidence=f"{path} → {evidence}",
                        details=(
                            f"Example env file accessible at {path}. "
                            "If real credentials were copied in (common mistake), they are now exposed."
                        ),
                        request={"path": path, "method": "GET"},
                        response={"status": status_code, "body_preview": body[:200]},
                        duration_ms=duration,
                    )

                await asyncio.sleep(PROBE_THROTTLE_S)

            return self._make_result(
                variant="env_example",
                status=Status.DEFENDED,
                evidence=f"All {len(paths)} example env paths returned non-200 responses",
                details=f"Tested: {', '.join(paths)}",
                request={"paths_tested": paths},
                duration_ms=(time.monotonic() - start) * 1000,
            )

        except Exception as e:
            return self._make_result(
                variant="env_example",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _probe_docker_env(self, client) -> AttackResult:
        """Probe for Docker/compose files that may expose environment variables."""
        start = time.monotonic()
        paths = [
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/docker-compose.prod.yml",
            "/Dockerfile",
            "/.dockerenv",
        ]

        DOCKER_SECRET_PATTERNS = [
            "ENV ", "environment:", "POSTGRES_PASSWORD", "MYSQL_PASSWORD",
            "DB_PASSWORD", "SECRET_KEY", "API_KEY",
        ]

        try:
            for path in paths:
                status_code, body, headers = await client.get(path, cookies={})

                if status_code == 200:
                    has_secrets = any(pat in body for pat in DOCKER_SECRET_PATTERNS)
                    duration = (time.monotonic() - start) * 1000
                    if has_secrets:
                        return self._make_result(
                            variant="docker_env",
                            status=Status.VULNERABLE,
                            evidence=f"{path} → HTTP 200 with environment variable definitions",
                            details=(
                                f"Docker configuration file exposed at {path}. "
                                "Contains environment variable definitions that may include secrets."
                            ),
                            request={"path": path, "method": "GET"},
                            response={"status": status_code, "body_preview": body[:300]},
                            duration_ms=duration,
                        )
                    else:
                        return self._make_result(
                            variant="docker_env",
                            status=Status.PARTIAL,
                            evidence=f"{path} → HTTP 200 but no environment variable patterns detected",
                            details="Docker file is accessible but may not contain secrets. Manual review recommended.",
                            request={"path": path},
                            response={"status": status_code, "body_preview": body[:300]},
                            duration_ms=duration,
                        )

                await asyncio.sleep(PROBE_THROTTLE_S)

            return self._make_result(
                variant="docker_env",
                status=Status.DEFENDED,
                evidence=f"All {len(paths)} Docker file paths returned non-200 responses",
                details=f"Tested: {', '.join(paths)}",
                request={"paths_tested": paths},
                duration_ms=(time.monotonic() - start) * 1000,
            )

        except Exception as e:
            return self._make_result(
                variant="docker_env",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _probe_config_files(self, client) -> AttackResult:
        """Probe for common application configuration files served over HTTP."""
        start = time.monotonic()
        paths = [
            "/config.php",
            "/config.yml",
            "/config.yaml",
            "/settings.py",
            "/application.properties",
            "/app.config",
            "/web.config",
            "/database.yml",
            "/secrets.yml",
        ]

        try:
            for path in paths:
                status_code, body, headers = await client.get(path, cookies={})
                status, evidence = self._classify_response(status_code, body, "config_files")

                if status in (Status.VULNERABLE, Status.PARTIAL):
                    duration = (time.monotonic() - start) * 1000
                    return self._make_result(
                        variant="config_files",
                        status=status,
                        evidence=f"{path} → {evidence}",
                        details=(
                            f"Configuration file accessible at {path}. "
                            + ("Contains secret key patterns indicating credential exposure."
                               if status == Status.VULNERABLE
                               else "File is accessible; manual review recommended.")
                        ),
                        request={"path": path, "method": "GET"},
                        response={"status": status_code, "body_preview": body[:300]},
                        duration_ms=duration,
                    )

                await asyncio.sleep(PROBE_THROTTLE_S)

            return self._make_result(
                variant="config_files",
                status=Status.DEFENDED,
                evidence=f"All {len(paths)} config file paths returned non-200 responses",
                details=f"Tested: {', '.join(paths)}",
                request={"paths_tested": paths},
                duration_ms=(time.monotonic() - start) * 1000,
            )

        except Exception as e:
            return self._make_result(
                variant="config_files",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )
