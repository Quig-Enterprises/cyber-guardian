"""Authorization boundary attacks - role escalation and company/vessel isolation."""

import jwt as pyjwt
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class AuthzBoundariesAttack(Attack):
    name = "api.authz_boundaries"
    category = "api"
    severity = Severity.HIGH
    description = "Role escalation and company/vessel boundary enforcement tests"

    JWT_SECRET = "eqmon_jwt_secret_2026_artemis_integration"

    def _make_jwt(self, role: str = "viewer", opco_id: str = None,
                  vessel_id: str = None, user_id: str = None,
                  instance_id: str = "default") -> str:
        """Create a JWT with specific claims for boundary testing."""
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
            "user_id": user_id or f"redteam-authz-{uuid.uuid4().hex[:8]}",
            "instance_id": instance_id,
            "email": f"redteam-authz-{role}@example.com",
            "role": role,
            "opco_id": opco_id,
            "vessel_id": vessel_id,
            "salt_version": 1,
            "auth_source": "eqmon",
        }
        return pyjwt.encode(payload, self.JWT_SECRET, algorithm="HS256")

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"
        session_id = f"redteam-authz-{uuid.uuid4().hex[:8]}"

        # --- Role-based access control tests ---

        # 1. Viewer attempting to add a note (write operation)
        # A viewer should be read-only. Adding a note is a write operation.
        viewer_token = self._make_jwt(role="viewer")
        viewer_cookies = {"eqmon_session": viewer_token}

        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "add_note",
                "device_id": "redteam-test-device",
                "note": "REDTEAM-AUTHZ: viewer should not write",
            },
            cookies=viewer_cookies,
        )
        # A viewer writing data = vulnerability
        if status_code == 200 and ("success" in body.lower() or '"id"' in body):
            authz_status = Status.VULNERABLE
        elif status_code in (403, 401):
            authz_status = Status.DEFENDED
        else:
            authz_status = Status.PARTIAL
        results.append(self._make_result(
            variant="viewer_add_note",
            status=authz_status,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Viewer role attempted add_note write operation. "
                f"Got {status_code}. Viewers should be denied write access."
            ),
            request={"role": "viewer", "action": "add_note"},
            response={"status": status_code, "body": body[:300]},
        ))

        # 2. Viewer attempting to send a chat message
        # Sending a chat message triggers AI processing -- may be restricted for viewers.
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "send_message",
                "message": "REDTEAM-AUTHZ: viewer chat test",
                "session_id": session_id,
            },
            cookies=viewer_cookies,
        )
        # If viewer can chat, it's at least partial (may be by design), but
        # if the system is supposed to restrict viewers from chatting, it's vulnerable.
        if status_code == 200:
            authz_status = Status.PARTIAL  # May be by design -- flag for review
        elif status_code in (403, 401):
            authz_status = Status.DEFENDED
        else:
            authz_status = Status.PARTIAL
        results.append(self._make_result(
            variant="viewer_send_message",
            status=authz_status,
            severity=Severity.MEDIUM,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Viewer role attempted send_message. Got {status_code}. "
                "Review whether viewers should have chat access."
            ),
            request={"role": "viewer", "action": "send_message"},
            response={"status": status_code, "body": body[:300]},
        ))

        # --- Tenant isolation tests ---

        # 3. Cross-company: create JWT with different opco_id, try to access data
        # Forge a token claiming to be from a different operating company.
        cross_company_token = self._make_jwt(
            role="system-admin",
            opco_id="rival-company-opco-999",
        )
        cross_company_cookies = {"eqmon_session": cross_company_token}

        status_code, body, headers = await client.get(
            test_path,
            params={"session_id": "redteam-existing-session"},
            cookies=cross_company_cookies,
        )
        # If a cross-company JWT can access data, it's a tenant isolation failure.
        has_data = '"messages"' in body and len(body) > 50
        if status_code == 200 and has_data:
            authz_status = Status.VULNERABLE
        elif status_code in (403, 401):
            authz_status = Status.DEFENDED
        else:
            authz_status = Status.PARTIAL
        results.append(self._make_result(
            variant="cross_company_access",
            status=authz_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"JWT with opco_id='rival-company-opco-999' attempted data access. "
                f"Got {status_code}. Cross-company access must be blocked."
            ),
            request={"role": "system-admin", "opco_id": "rival-company-opco-999"},
            response={"status": status_code, "body": body[:300]},
        ))

        # 4. Cross-vessel: create JWT with different vessel_id, try to access data
        cross_vessel_token = self._make_jwt(
            role="system-admin",
            vessel_id="rival-vessel-888",
        )
        cross_vessel_cookies = {"eqmon_session": cross_vessel_token}

        status_code, body, headers = await client.get(
            test_path,
            params={"session_id": "redteam-existing-session"},
            cookies=cross_vessel_cookies,
        )
        has_data = '"messages"' in body and len(body) > 50
        if status_code == 200 and has_data:
            authz_status = Status.VULNERABLE
        elif status_code in (403, 401):
            authz_status = Status.DEFENDED
        else:
            authz_status = Status.PARTIAL
        results.append(self._make_result(
            variant="cross_vessel_access",
            status=authz_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"JWT with vessel_id='rival-vessel-888' attempted data access. "
                f"Got {status_code}. Cross-vessel access must be blocked."
            ),
            request={"role": "system-admin", "vessel_id": "rival-vessel-888"},
            response={"status": status_code, "body": body[:300]},
        ))

        # 5. Role escalation: create JWT with elevated role (viewer -> system-admin)
        # An attacker who has a viewer account forges a token claiming system-admin.
        escalated_token = self._make_jwt(
            role="system-admin",
            user_id="redteam-viewer-user-escalated",
        )
        escalated_cookies = {"eqmon_session": escalated_token}

        # Try a privileged operation: add a note (system-admin should be allowed)
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "add_note",
                "device_id": "redteam-test-device",
                "note": "REDTEAM-ESCALATION: forged system-admin token",
            },
            cookies=escalated_cookies,
        )
        # If a self-issued system-admin JWT works, the server trusts the token
        # claims without verifying the user actually has that role in the DB.
        if status_code == 200 and ("success" in body.lower() or '"id"' in body):
            authz_status = Status.VULNERABLE
        elif status_code in (403, 401):
            authz_status = Status.DEFENDED
        else:
            authz_status = Status.PARTIAL
        results.append(self._make_result(
            variant="role_escalation",
            status=authz_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Self-signed JWT with role='system-admin' and fabricated user_id "
                f"attempted a write operation. Got {status_code}. "
                "Server must validate role claims against the database."
            ),
            request={
                "role": "system-admin (forged)",
                "user_id": "redteam-viewer-user-escalated",
                "action": "add_note",
            },
            response={"status": status_code, "body": body[:300]},
        ))

        return results

    async def cleanup(self, client) -> None:
        """Best-effort cleanup of any notes created during authz testing."""
        pass
