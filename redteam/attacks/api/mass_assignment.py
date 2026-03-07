"""Mass assignment and parameter pollution vulnerability detection.

Tests whether API endpoints accept and process fields that should be
server-controlled (role, permissions, timestamps, IDs) and whether
duplicate parameter handling is inconsistent.

Evaluation:
- Server accepts and reflects injected admin/role fields -> VULNERABLE
- Server reflects injected metadata fields (id, timestamps) -> VULNERABLE
- Duplicate parameters cause inconsistent behavior -> PARTIAL
- All injected fields are ignored -> DEFENDED

IMPORTANT: Uses clearly fake values and test endpoints only.
Never modifies production data.
"""

import asyncio
import json
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class MassAssignmentAttack(Attack):
    """Detect mass assignment and parameter pollution vulnerabilities."""

    name = "api.mass_assignment"
    category = "api"
    severity = Severity.HIGH
    description = "Mass assignment and parameter pollution vulnerability detection"
    target_types = {"app", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all mass assignment variants."""
        results = []
        endpoints = self._get_test_endpoints()

        results.append(await self._check_role_escalation(client, endpoints))
        results.append(await self._check_field_injection(client, endpoints))
        results.append(await self._check_parameter_pollution(client, endpoints))

        return results

    async def _check_role_escalation(self, client, endpoints: list[str]) -> AttackResult:
        """role_escalation: POST/PUT with admin role fields and check if accepted."""
        start = time.monotonic()
        findings = []

        # Payloads that attempt privilege escalation via mass assignment
        escalation_payloads = [
            {
                "action": "update_profile",
                "name": "redteam_test_user",
                "role": "admin",
                "is_admin": True,
                "permission_level": 9999,
            },
            {
                "action": "update_profile",
                "name": "redteam_test_user",
                "user_type": "superadmin",
                "admin": 1,
                "privileges": ["read", "write", "delete", "admin"],
            },
            {
                "action": "register",
                "username": "redteam_massassign_test",
                "password": "TestOnly!NoReal#Data123",
                "role": "administrator",
                "is_staff": True,
                "is_superuser": True,
            },
        ]

        # Fields that indicate privilege escalation was accepted
        escalation_fields = {
            "role", "is_admin", "permission_level", "user_type",
            "admin", "privileges", "is_staff", "is_superuser",
        }

        for endpoint in endpoints:
            for payload in escalation_payloads:
                try:
                    status_code, body, headers = await client.post(
                        endpoint, json_body=payload
                    )

                    if self._is_aws_mode():
                        await asyncio.sleep(0.2)

                    # Check if any escalation fields appear in response
                    try:
                        response_data = json.loads(body)
                    except (json.JSONDecodeError, TypeError):
                        continue

                    reflected = self._find_reflected_fields(
                        payload, response_data, escalation_fields
                    )
                    if reflected:
                        findings.append(
                            f"[{endpoint}] Reflected escalation fields: "
                            f"{', '.join(reflected)}"
                        )

                except Exception as e:
                    logger.debug("Error testing %s: %s", endpoint, e)
                    continue

        duration = (time.monotonic() - start) * 1000

        if findings:
            return self._make_result(
                variant="role_escalation",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"Server accepted {len(findings)} privilege escalation attempts",
                details=(
                    f"API endpoints reflect injected role/admin fields back in responses, "
                    f"indicating possible mass assignment vulnerability: "
                    f"{'; '.join(findings[:3])}"
                ),
                request={"endpoints_tested": endpoints,
                          "payloads_sent": len(escalation_payloads)},
                response={"findings": findings[:10]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="role_escalation",
                status=Status.DEFENDED,
                evidence="No privilege escalation fields accepted by the API",
                details=(
                    f"Sent {len(escalation_payloads)} payloads with admin/role fields to "
                    f"{len(endpoints)} endpoints - none were reflected in responses"
                ),
                request={"endpoints_tested": endpoints},
                response={"findings": []},
                duration_ms=duration,
            )

    async def _check_field_injection(self, client, endpoints: list[str]) -> AttackResult:
        """field_injection: POST with unexpected metadata fields and check reflection."""
        start = time.monotonic()
        findings = []

        # Fields that should be server-controlled, not client-settable
        injection_payloads = [
            {
                "action": "create",
                "name": "redteam_field_injection_test",
                "id": 999999,
                "created_at": "2000-01-01T00:00:00Z",
                "updated_at": "2000-01-01T00:00:00Z",
            },
            {
                "action": "update",
                "name": "redteam_field_injection_test",
                "user_id": 1,
                "owner_id": 1,
                "_internal_flag": True,
                "__version": 999,
            },
            {
                "action": "create",
                "title": "redteam_test",
                "status": "published",
                "approved": True,
                "verified": True,
                "deleted": False,
            },
        ]

        # Metadata fields that should not be client-settable
        metadata_fields = {
            "id", "created_at", "updated_at", "user_id", "owner_id",
            "_internal_flag", "__version", "status", "approved",
            "verified", "deleted",
        }

        for endpoint in endpoints:
            for payload in injection_payloads:
                try:
                    status_code, body, headers = await client.post(
                        endpoint, json_body=payload
                    )

                    if self._is_aws_mode():
                        await asyncio.sleep(0.2)

                    try:
                        response_data = json.loads(body)
                    except (json.JSONDecodeError, TypeError):
                        continue

                    reflected = self._find_reflected_fields(
                        payload, response_data, metadata_fields
                    )
                    if reflected:
                        findings.append(
                            f"[{endpoint}] Reflected metadata fields: "
                            f"{', '.join(reflected)}"
                        )

                except Exception as e:
                    logger.debug("Error testing %s: %s", endpoint, e)
                    continue

        duration = (time.monotonic() - start) * 1000

        if findings:
            return self._make_result(
                variant="field_injection",
                status=Status.VULNERABLE,
                evidence=f"Server accepted {len(findings)} field injection attempts",
                details=(
                    f"API endpoints reflect injected metadata fields (id, timestamps, "
                    f"internal flags) in responses: {'; '.join(findings[:3])}"
                ),
                request={"endpoints_tested": endpoints,
                          "payloads_sent": len(injection_payloads)},
                response={"findings": findings[:10]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="field_injection",
                status=Status.DEFENDED,
                evidence="No metadata field injection accepted",
                details=(
                    f"Sent {len(injection_payloads)} payloads with server-controlled fields to "
                    f"{len(endpoints)} endpoints - none were reflected"
                ),
                request={"endpoints_tested": endpoints},
                response={"findings": []},
                duration_ms=duration,
            )

    async def _check_parameter_pollution(self, client, endpoints: list[str]) -> AttackResult:
        """parameter_pollution: Send duplicate parameters and check for inconsistency."""
        start = time.monotonic()
        findings = []

        for endpoint in endpoints:
            try:
                # Test 1: Duplicate query parameters with different values
                # Send ?id=1&id=2 by manually constructing the path
                polluted_path = f"{endpoint}?id=1&id=2&action=get&action=delete"

                status_code_1, body_1, headers_1 = await client.get(
                    polluted_path, cookies={}
                )

                if self._is_aws_mode():
                    await asyncio.sleep(0.2)

                # Test 2: Normal single parameter
                normal_path = f"{endpoint}?id=1&action=get"
                status_code_2, body_2, headers_2 = await client.get(
                    normal_path, cookies={}
                )

                # Check for inconsistent behavior
                # If polluted request succeeds differently than normal, flag it
                if (status_code_1 != status_code_2 and
                        status_code_1 < 400):
                    findings.append(
                        f"[{endpoint}] Status differs: polluted={status_code_1} "
                        f"vs normal={status_code_2}"
                    )

                # Check if 'delete' action was processed from the duplicate
                if ("delete" in body_1.lower() and
                        "delete" not in body_2.lower()):
                    findings.append(
                        f"[{endpoint}] Polluted request processed 'delete' action "
                        f"from duplicate parameter"
                    )

            except Exception as e:
                logger.debug("Error testing parameter pollution on %s: %s", endpoint, e)
                continue

        duration = (time.monotonic() - start) * 1000

        if findings:
            return self._make_result(
                variant="parameter_pollution",
                status=Status.PARTIAL,
                evidence=f"Parameter pollution caused {len(findings)} behavioral differences",
                details=(
                    f"Duplicate query parameters cause inconsistent behavior: "
                    f"{'; '.join(findings[:3])}"
                ),
                request={"endpoints_tested": endpoints},
                response={"findings": findings[:10]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="parameter_pollution",
                status=Status.DEFENDED,
                evidence="No parameter pollution inconsistencies detected",
                details=(
                    f"Tested {len(endpoints)} endpoints with duplicate parameters - "
                    "behavior was consistent"
                ),
                request={"endpoints_tested": endpoints},
                response={"findings": []},
                duration_ms=duration,
            )

    @staticmethod
    def _find_reflected_fields(sent: dict, received, target_fields: set) -> list[str]:
        """Check if any target fields from sent payload appear in received response."""
        reflected = []

        if not isinstance(received, dict):
            return reflected

        for field in target_fields:
            if field in sent and field in received:
                sent_val = sent[field]
                recv_val = received[field]
                # Check if the value matches what we sent
                if str(sent_val) == str(recv_val):
                    reflected.append(f"{field}={recv_val}")

        return reflected
