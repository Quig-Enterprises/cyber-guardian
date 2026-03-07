"""OWASP API3:2023 - Excessive Data Exposure detection.

Tests API endpoints for responses that include sensitive fields, verbose
error messages with internal details, or user listings that return more
data than necessary.

Evaluation:
- Response contains sensitive field names (password, token, ssn, etc.) -> VULNERABLE
- Error responses contain stack traces, SQL, or internal paths -> VULNERABLE
- User listing returns excessive PII fields -> PARTIAL
- No excessive data found -> DEFENDED
"""

import asyncio
import json
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Sensitive field names that should never appear in API responses
SENSITIVE_FIELDS = {
    "password", "password_hash", "passwd", "pass_hash",
    "secret", "secret_key", "client_secret",
    "token", "access_token", "refresh_token", "auth_token",
    "ssn", "social_security",
    "credit_card", "card_number", "cc_number", "cvv", "cvc",
    "api_key", "apikey", "api_secret",
    "private_key", "privkey",
    "salt", "password_salt",
}

# Patterns indicating verbose error info
ERROR_PATTERNS = [
    "Stack trace:",
    "Traceback (most recent",
    "#0 ",
    "Fatal error:",
    "SQLSTATE",
    "PDOException",
    "pg_query",
    "mysql_",
    "/var/www/",
    "/opt/",
    "/home/",
    ".php on line",
    "at line ",
    "SELECT ",
    "INSERT INTO",
    "UPDATE ",
    "DELETE FROM",
]


class ExcessiveDataAttack(Attack):
    """Detect excessive data exposure in API responses."""

    name = "api.excessive_data"
    category = "api"
    severity = Severity.MEDIUM
    description = "OWASP API3:2023 - Excessive Data Exposure detection"
    target_types = {"app", "generic"}

    def _scan_dict_for_sensitive_fields(self, data, path: str = "") -> list[str]:
        """Recursively scan a dict/list for sensitive field names."""
        findings = []

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                key_lower = key.lower().strip()
                if key_lower in SENSITIVE_FIELDS:
                    # Mask the actual value
                    val_preview = str(value)[:20] + "..." if len(str(value)) > 20 else str(value)
                    findings.append(f"{current_path}={val_preview}")
                # Recurse
                findings.extend(self._scan_dict_for_sensitive_fields(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data[:10]):  # Limit to first 10 items
                findings.extend(
                    self._scan_dict_for_sensitive_fields(item, f"{path}[{i}]")
                )

        return findings

    async def execute(self, client) -> list[AttackResult]:
        """Run all excessive data exposure variants."""
        results = []
        endpoints = self._get_test_endpoints()

        results.append(await self._check_sensitive_fields(client, endpoints))
        results.append(await self._check_verbose_errors(client, endpoints))
        results.append(await self._check_user_data_leakage(client, endpoints))

        return results

    async def _check_sensitive_fields(self, client, endpoints: list[str]) -> AttackResult:
        """sensitive_fields_in_response: Scan JSON responses for sensitive field names."""
        start = time.monotonic()
        all_findings = []

        for endpoint in endpoints:
            try:
                status_code, body, headers = await client.get(endpoint, cookies={})

                if self._is_aws_mode():
                    await asyncio.sleep(0.1)

                # Try to parse as JSON
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    continue

                findings = self._scan_dict_for_sensitive_fields(data)
                for f in findings:
                    all_findings.append(f"[{endpoint}] {f}")

            except Exception as e:
                logger.debug("Error checking %s: %s", endpoint, e)
                continue

        duration = (time.monotonic() - start) * 1000

        if all_findings:
            return self._make_result(
                variant="sensitive_fields_in_response",
                status=Status.VULNERABLE,
                evidence=f"Found {len(all_findings)} sensitive fields in API responses",
                details=(
                    f"Sensitive data exposed in responses: "
                    f"{'; '.join(all_findings[:5])}"
                    f"{f' (+{len(all_findings)-5} more)' if len(all_findings) > 5 else ''}"
                ),
                request={"endpoints_checked": endpoints},
                response={"findings": all_findings[:10]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="sensitive_fields_in_response",
                status=Status.DEFENDED,
                evidence=f"No sensitive fields found in {len(endpoints)} endpoint responses",
                details="API responses do not contain sensitive field names",
                request={"endpoints_checked": endpoints},
                response={"findings": []},
                duration_ms=duration,
            )

    async def _check_verbose_errors(self, client, endpoints: list[str]) -> AttackResult:
        """verbose_errors: Send malformed requests and check for stack traces."""
        start = time.monotonic()
        all_findings = []

        # Malformed payloads designed to trigger errors
        malformed_payloads = [
            {"action": None},
            {"id": "'; DROP TABLE--"},
            {"action": "A" * 5000},
            {"data": {"nested": {"deep": [1, 2, [3, [4]]]}}},
        ]

        for endpoint in endpoints:
            for payload in malformed_payloads:
                try:
                    status_code, body, headers = await client.post(
                        endpoint, json_body=payload
                    )

                    if self._is_aws_mode():
                        await asyncio.sleep(0.1)

                    body_lower = body.lower()
                    for pattern in ERROR_PATTERNS:
                        if pattern.lower() in body_lower:
                            all_findings.append(
                                f"[{endpoint}] Pattern '{pattern}' found in "
                                f"HTTP {status_code} response"
                            )

                except Exception as e:
                    logger.debug("Error probing %s: %s", endpoint, e)
                    continue

        duration = (time.monotonic() - start) * 1000

        if all_findings:
            return self._make_result(
                variant="verbose_errors",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"Found {len(all_findings)} verbose error indicators",
                details=(
                    f"Error responses leak internal details: "
                    f"{'; '.join(all_findings[:5])}"
                    f"{f' (+{len(all_findings)-5} more)' if len(all_findings) > 5 else ''}"
                ),
                request={"endpoints_checked": endpoints,
                          "payloads_sent": len(malformed_payloads)},
                response={"findings": all_findings[:10]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="verbose_errors",
                status=Status.DEFENDED,
                evidence="No verbose error details found in error responses",
                details=(
                    f"Sent {len(malformed_payloads)} malformed payloads to "
                    f"{len(endpoints)} endpoints - no stack traces or internal details leaked"
                ),
                request={"endpoints_checked": endpoints,
                          "payloads_sent": len(malformed_payloads)},
                response={"findings": []},
                duration_ms=duration,
            )

    async def _check_user_data_leakage(self, client, endpoints: list[str]) -> AttackResult:
        """user_data_leakage: Check if user-related endpoints return excessive fields."""
        start = time.monotonic()

        # Common user listing endpoints to probe
        user_endpoints = [
            "/api/users",
            "/api/v1/users",
            "/wp-json/wp/v2/users",
            "/api/accounts",
            "/api/members",
        ]

        # PII fields that may be excessive in list responses
        excessive_fields = {
            "email", "phone", "phone_number", "address", "date_of_birth",
            "dob", "age", "gender", "ip_address", "last_login_ip",
            "billing_address", "shipping_address",
        }

        findings = []

        for endpoint in user_endpoints:
            try:
                status_code, body, headers = await client.get(endpoint, cookies={})

                if self._is_aws_mode():
                    await asyncio.sleep(0.1)

                if status_code >= 400:
                    continue

                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    continue

                # Check if response is a list of user objects
                items = data if isinstance(data, list) else data.get("data", data.get("results", []))
                if not isinstance(items, list) or not items:
                    continue

                # Check first item for excessive fields
                first_item = items[0] if isinstance(items[0], dict) else {}
                exposed = []
                for field_name in first_item.keys():
                    if field_name.lower() in excessive_fields:
                        exposed.append(field_name)

                if exposed:
                    findings.append(
                        f"[{endpoint}] Exposes: {', '.join(exposed)} "
                        f"({len(items)} records)"
                    )

            except Exception as e:
                logger.debug("Error checking user endpoint %s: %s", endpoint, e)
                continue

        duration = (time.monotonic() - start) * 1000

        if findings:
            return self._make_result(
                variant="user_data_leakage",
                status=Status.PARTIAL,
                evidence=f"User endpoints expose potentially excessive fields",
                details=(
                    f"User-related endpoints return more data than likely needed: "
                    f"{'; '.join(findings[:5])}"
                ),
                request={"endpoints_probed": user_endpoints},
                response={"findings": findings[:10]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="user_data_leakage",
                status=Status.DEFENDED,
                evidence="No excessive user data leakage detected",
                details=(
                    f"Probed {len(user_endpoints)} user-related endpoints - "
                    "none returned excessive PII fields or were not accessible"
                ),
                request={"endpoints_probed": user_endpoints},
                response={"findings": []},
                duration_ms=duration,
            )
