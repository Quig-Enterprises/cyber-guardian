"""Dual authorization bypass — NIST SP 800-172 Requirement 3.1.1e.

NIST SP 800-172 requirement 3.1.1e mandates that organizations implement
dual authorization (two-person control) for critical or sensitive operations.
No single individual should be able to execute a critical operation without
a second authorized party approving the action. This prevents insider threats
and ensures accountability for high-impact changes.

This module tests whether the following critical operations can be performed
by a single authenticated admin session without any approval workflow:

  - Changing another user's role (privilege escalation)
  - Deleting or deactivating a user account
  - Modifying critical service configurations
  - Bulk-exporting all user or audit log data
  - Changing security-critical settings (MFA policy, password policy, session timeout)

For each variant, a SUCCESS (2xx) from a single session is a finding because
it means dual authorization is NOT enforced. A 403 with an approval-required
message is the expected defended behavior.
"""

import json
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class DualAuthorizationBypassAttack(Attack):
    name = "compliance.dual_authorization_bypass"
    category = "compliance"
    severity = Severity.HIGH
    description = (
        "NIST SP 800-172 3.1.1e — Verify critical operations require dual "
        "authorization (two-person control) and cannot be executed by a single "
        "authenticated admin session alone"
    )

    # Keyword signatures that indicate a dual-auth / approval workflow is in place
    APPROVAL_KEYWORDS = (
        "approval",
        "approve",
        "two-person",
        "dual",
        "second",
        "authorize",
        "pending",
        "workflow",
        "confirm",
    )

    def _requires_approval(self, body: str) -> bool:
        """Return True if the response body mentions an approval requirement."""
        lower = body.lower()
        return any(kw in lower for kw in self.APPROVAL_KEYWORDS)

    def _parse_body(self, raw: str) -> dict:
        """Attempt to parse raw body as JSON; fall back to a plain dict."""
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"raw": str(raw)[:500]}

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. single_admin_role_change
        #    A single admin promotes another account to system-admin without
        #    a second approver. NIST 3.1.1e: role changes that expand privilege
        #    are a critical operation and must require dual authorization.
        # ----------------------------------------------------------------
        target_user_id = f"redteam-{uuid.uuid4().hex[:8]}"
        status_code, body, headers = await client.post(
            "/api/admin/users.php",
            json_body={
                "action": "change_role",
                "user_id": target_user_id,
                "new_role": "system-admin",
            },
        )

        approval_required = self._requires_approval(body)

        if status_code in (200, 201, 204):
            role_status = Status.VULNERABLE
            evidence = (
                f"Role change accepted with HTTP {status_code} from a single admin session. "
                "No dual authorization enforced."
            )
            detail = (
                "A single authenticated admin was able to promote a user to system-admin "
                "without a second approver. NIST SP 800-172 3.1.1e requires dual "
                "authorization for privilege-expanding operations."
            )
        elif status_code == 403:
            if approval_required:
                role_status = Status.DEFENDED
                evidence = f"HTTP 403 with approval-required message — dual auth enforced."
                detail = "Server correctly rejected the single-admin role change and indicated an approval workflow."
            else:
                role_status = Status.DEFENDED
                evidence = f"HTTP 403 — operation denied for single admin session."
                detail = "Role change blocked; server returned 403. Dual authorization appears enforced."
        elif status_code in (404, 405):
            role_status = Status.PARTIAL
            evidence = f"Endpoint returned HTTP {status_code} — endpoint may not exist."
            detail = (
                f"POST /api/admin/users.php for role change returned {status_code}. "
                "The endpoint should exist and enforce dual authorization per NIST 3.1.1e."
            )
        else:
            role_status = Status.ERROR
            evidence = f"Unexpected HTTP {status_code} from role-change endpoint."
            detail = f"Could not determine dual-auth status. Body: {body[:300]}"

        results.append(self._make_result(
            variant="single_admin_role_change",
            status=role_status,
            evidence=evidence,
            details=detail,
            request={
                "method": "POST",
                "endpoint": "/api/admin/users.php",
                "body": {"action": "change_role", "user_id": target_user_id, "new_role": "system-admin"},
            },
            response={"status": status_code, "body": self._parse_body(body)},
        ))

        # ----------------------------------------------------------------
        # 2. single_admin_user_delete
        #    A single admin deletes/deactivates a user account without a
        #    second approver. User deletion is irreversible and classified as
        #    a critical operation under 3.1.1e.
        # ----------------------------------------------------------------
        delete_user_id = f"redteam-{uuid.uuid4().hex[:8]}"
        status_code, body, headers = await client.post(
            "/api/admin/users.php",
            json_body={
                "action": "delete",
                "user_id": delete_user_id,
            },
        )

        approval_required = self._requires_approval(body)

        if status_code in (200, 201, 204):
            delete_status = Status.VULNERABLE
            evidence = (
                f"User deletion accepted with HTTP {status_code} from a single admin session. "
                "No dual authorization enforced."
            )
            detail = (
                "A single authenticated admin deleted a user account without a second approver. "
                "NIST SP 800-172 3.1.1e requires dual authorization for destructive operations "
                "such as account deletion."
            )
        elif status_code == 403:
            delete_status = Status.DEFENDED
            evidence = (
                f"HTTP 403 — deletion denied for single admin. "
                f"Approval workflow indicated: {approval_required}."
            )
            detail = "User deletion correctly blocked for a single admin session."
        elif status_code in (404, 405):
            delete_status = Status.PARTIAL
            evidence = f"Endpoint returned HTTP {status_code}."
            detail = (
                f"DELETE /api/admin/users.php returned {status_code}. "
                "Endpoint should exist and enforce dual authorization per NIST 3.1.1e."
            )
        else:
            delete_status = Status.ERROR
            evidence = f"Unexpected HTTP {status_code} from user-delete endpoint."
            detail = f"Could not determine dual-auth status. Body: {body[:300]}"

        results.append(self._make_result(
            variant="single_admin_user_delete",
            status=delete_status,
            evidence=evidence,
            details=detail,
            request={
                "method": "POST",
                "endpoint": "/api/admin/users.php",
                "body": {"action": "delete", "user_id": delete_user_id},
            },
            response={"status": status_code, "body": self._parse_body(body)},
        ))

        # ----------------------------------------------------------------
        # 3. single_admin_service_config
        #    A single admin modifies critical service configuration without
        #    a second approver. Infrastructure configuration changes can have
        #    system-wide impact and qualify as critical operations.
        # ----------------------------------------------------------------
        config_key = f"redteam_test_param_{uuid.uuid4().hex[:6]}"
        status_code, body, headers = await client.post(
            "/api/admin/settings.php",
            json_body={
                "action": "update",
                "key": config_key,
                "value": "redteam-injected-value",
            },
        )

        approval_required = self._requires_approval(body)

        if status_code in (200, 201, 204):
            config_status = Status.VULNERABLE
            evidence = (
                f"Service configuration change accepted with HTTP {status_code} "
                "from a single admin session. No dual authorization enforced."
            )
            detail = (
                "A single authenticated admin modified a critical service configuration "
                "parameter without a second approver. NIST SP 800-172 3.1.1e requires "
                "dual authorization for changes that affect system-wide configuration."
            )
        elif status_code == 403:
            config_status = Status.DEFENDED
            evidence = (
                f"HTTP 403 — configuration change denied for single admin. "
                f"Approval workflow indicated: {approval_required}."
            )
            detail = "Service configuration change correctly blocked for a single admin session."
        elif status_code in (404, 405):
            config_status = Status.PARTIAL
            evidence = f"Endpoint returned HTTP {status_code}."
            detail = (
                f"POST /api/admin/settings.php returned {status_code}. "
                "Endpoint should exist and enforce dual authorization per NIST 3.1.1e."
            )
        else:
            config_status = Status.ERROR
            evidence = f"Unexpected HTTP {status_code} from service-config endpoint."
            detail = f"Could not determine dual-auth status. Body: {body[:300]}"

        results.append(self._make_result(
            variant="single_admin_service_config",
            status=config_status,
            evidence=evidence,
            details=detail,
            request={
                "method": "POST",
                "endpoint": "/api/admin/settings.php",
                "body": {"action": "update", "key": config_key, "value": "redteam-injected-value"},
            },
            response={"status": status_code, "body": self._parse_body(body)},
        ))

        # ----------------------------------------------------------------
        # 4. single_admin_bulk_export
        #    A single admin exports all user records or audit logs without a
        #    second approver. Bulk data export is a high-risk operation that
        #    can facilitate data exfiltration and must require dual authorization.
        # ----------------------------------------------------------------
        status_code, body, headers = await client.get(
            "/api/admin/users.php",
            params={"action": "export"},
        )

        approval_required = self._requires_approval(body)

        if status_code in (200, 201):
            # Check if the response looks like actual bulk data
            body_lower = body.lower()
            has_bulk_data = (
                len(body) > 200
                or "email" in body_lower
                or "username" in body_lower
                or "user_id" in body_lower
                or body_lower.startswith("[")
                or body_lower.startswith("{")
            )
            if has_bulk_data:
                export_status = Status.VULNERABLE
                evidence = (
                    f"Bulk export returned HTTP {status_code} with {len(body)} bytes of data "
                    "from a single admin session. No dual authorization enforced."
                )
                detail = (
                    "A single authenticated admin exported bulk user/audit data without a "
                    "second approver. NIST SP 800-172 3.1.1e requires dual authorization "
                    "for mass data export operations that could facilitate exfiltration."
                )
            else:
                export_status = Status.PARTIAL
                evidence = (
                    f"Bulk export endpoint returned HTTP {status_code} but body appears "
                    "empty or non-data. Cannot confirm dual-auth enforcement."
                )
                detail = (
                    "Export endpoint responded but did not clearly return bulk data. "
                    "Manual review required to determine if dual authorization is enforced."
                )
        elif status_code == 403:
            export_status = Status.DEFENDED
            evidence = (
                f"HTTP 403 — bulk export denied for single admin. "
                f"Approval workflow indicated: {approval_required}."
            )
            detail = "Bulk export correctly blocked for a single admin session."
        elif status_code in (404, 405):
            export_status = Status.PARTIAL
            evidence = f"Bulk export endpoint returned HTTP {status_code}."
            detail = (
                f"GET /api/admin/users.php?action=export returned {status_code}. "
                "A bulk export endpoint should exist and enforce dual authorization per NIST 3.1.1e."
            )
        else:
            export_status = Status.ERROR
            evidence = f"Unexpected HTTP {status_code} from bulk-export endpoint."
            detail = f"Could not determine dual-auth status. Body: {body[:300]}"

        results.append(self._make_result(
            variant="single_admin_bulk_export",
            status=export_status,
            evidence=evidence,
            details=detail,
            request={
                "method": "GET",
                "endpoint": "/api/admin/users.php",
                "params": {"action": "export"},
            },
            response={"status": status_code, "body_length": len(body), "body_preview": body[:300]},
        ))

        # ----------------------------------------------------------------
        # 5. single_admin_security_settings
        #    A single admin changes security-critical settings (MFA policy,
        #    password complexity, session timeout) without a second approver.
        #    These settings directly affect the security posture of all users
        #    and are explicitly critical operations under NIST 3.1.1e.
        # ----------------------------------------------------------------
        status_code, body, headers = await client.post(
            "/api/admin/settings.php",
            json_body={
                "action": "update_security",
                "mfa_required": False,
                "password_min_length": 4,
                "session_timeout_minutes": 10080,  # 7 days — intentionally insecure
            },
        )

        approval_required = self._requires_approval(body)

        if status_code in (200, 201, 204):
            sec_status = Status.VULNERABLE
            evidence = (
                f"Security settings change accepted with HTTP {status_code} from a single "
                "admin session. No dual authorization enforced."
            )
            detail = (
                "A single authenticated admin was able to weaken security-critical settings "
                "(disabled MFA, reduced password length, extended session timeout) without a "
                "second approver. NIST SP 800-172 3.1.1e requires dual authorization for "
                "changes to authentication and session security policies."
            )
        elif status_code == 403:
            sec_status = Status.DEFENDED
            evidence = (
                f"HTTP 403 — security settings change denied for single admin. "
                f"Approval workflow indicated: {approval_required}."
            )
            detail = (
                "Security settings change correctly blocked for a single admin session. "
                "Dual authorization appears enforced for authentication policy changes."
            )
        elif status_code in (404, 405):
            sec_status = Status.PARTIAL
            evidence = f"Security settings endpoint returned HTTP {status_code}."
            detail = (
                f"POST /api/admin/settings.php with action=update_security returned {status_code}. "
                "A security settings endpoint should exist and enforce dual authorization per NIST 3.1.1e."
            )
        else:
            sec_status = Status.ERROR
            evidence = f"Unexpected HTTP {status_code} from security-settings endpoint."
            detail = f"Could not determine dual-auth status. Body: {body[:300]}"

        results.append(self._make_result(
            variant="single_admin_security_settings",
            status=sec_status,
            evidence=evidence,
            details=detail,
            request={
                "method": "POST",
                "endpoint": "/api/admin/settings.php",
                "body": {
                    "action": "update_security",
                    "mfa_required": False,
                    "password_min_length": 4,
                    "session_timeout_minutes": 10080,
                },
            },
            response={"status": status_code, "body": self._parse_body(body)},
        ))

        return results
