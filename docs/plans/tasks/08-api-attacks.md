# Task 08: API Security Attack Modules

Attack modules targeting the EQMON API layer. These test authentication bypass, authorization boundaries, injection, input validation, rate limiting, and error information leakage.

## Target System Details

- Base URL: `http://localhost:8081/eqmon`
- Auth: JWT in httpOnly cookie `eqmon_session`, HS256, secret `eqmon_jwt_secret_2026_artemis_integration`
- JWT payload fields: `user_id`, `instance_id`, `email`, `role`, `opco_id`, `vessel_id`, `salt_version`, `auth_source`
- Instance ID: `"default"`
- Sample analysis_id: `d381c227-4ae2-442b-bc04-970fecc7ca9e`
- CORS: `Access-Control-Allow-Origin: *` on all endpoints
- Error handling: PDOException messages exposed to client

### Endpoints Under Test

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/ai_chat.php` | `{action: "send_message", message: "...", session_id/analysis_id: "..."}` |
| POST | `/api/ai_chat.php` | `{action: "add_note", device_id: "...", note: "..."}` |
| GET | `/api/ai_chat.php?analysis_id=UUID` or `?session_id=UUID` | Fetch chat history |
| DELETE | `/api/ai_chat.php?action=delete_note&id=N` | Delete a bearing note |

## Files to Create

1. `redteam/attacks/api/auth_bypass.py` - JWT manipulation attacks (7 variants)
2. `redteam/attacks/api/idor.py` - Cross-user/cross-tenant data access (5 variants)
3. `redteam/attacks/api/authz_boundaries.py` - Role/company/vessel boundary tests (5 variants)
4. `redteam/attacks/api/injection.py` - SQL injection (6 variants)
5. `redteam/attacks/api/input_validation.py` - Malformed input (6 variants)
6. `redteam/attacks/api/rate_limiting.py` - Flood testing (3 variants)
7. `redteam/attacks/api/error_leakage.py` - Information disclosure (4 variants)

---

## redteam/attacks/api/auth_bypass.py

Uses PyJWT to craft malicious tokens. Tests 7 ways to bypass authentication:
1. No cookie at all
2. Expired JWT
3. Wrong signing key
4. Tampered payload (fabricated instance_id)
5. "none" algorithm attack
6. Empty cookie value
7. Malformed JWT string

```python
"""Authentication bypass attacks via JWT manipulation."""

import jwt as pyjwt  # PyJWT
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class AuthBypassAttack(Attack):
    name = "api.auth_bypass"
    category = "api"
    severity = Severity.CRITICAL
    description = "JWT authentication bypass via token manipulation"

    JWT_SECRET = "eqmon_jwt_secret_2026_artemis_integration"

    def _make_valid_payload(self, **overrides) -> dict:
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
            "user_id": "redteam-fake-user",
            "instance_id": "default",
            "email": "fake@test.com",
            "role": "system-admin",
            "opco_id": None,
            "vessel_id": None,
            "salt_version": 1,
            "auth_source": "eqmon",
        }
        payload.update(overrides)
        return payload

    def _encode_jwt(self, payload: dict, secret: str = None, algorithm: str = "HS256") -> str:
        return pyjwt.encode(payload, secret or self.JWT_SECRET, algorithm=algorithm)

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"
        test_params = {"session_id": f"redteam-{uuid.uuid4().hex[:8]}"}

        # 1. No cookie at all - request without any auth
        status_code, body, headers = await client.get(test_path, params=test_params, cookies={})
        results.append(self._make_result(
            variant="no_cookie",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=(
                f"Request with no auth cookie returned {status_code}"
                + (" (expected 401)" if status_code == 401 else " - SHOULD BE 401!")
            ),
            request={"path": test_path, "cookies": "none"},
            response={"status": status_code, "body": body[:200]},
        ))

        # 2. Expired JWT - create a token with exp in the past
        expired_payload = self._make_valid_payload(exp=int(time.time()) - 3600)
        expired_token = self._encode_jwt(expired_payload)
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": expired_token},
        )
        results.append(self._make_result(
            variant="expired_jwt",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=f"Expired JWT (exp=-1h) returned {status_code}",
            request={"token": "expired (-1h)"},
            response={"status": status_code},
        ))

        # 3. Wrong signing key - sign with "totally_wrong_secret"
        wrong_key_token = self._encode_jwt(
            self._make_valid_payload(), secret="totally_wrong_secret",
        )
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": wrong_key_token},
        )
        results.append(self._make_result(
            variant="wrong_signing_key",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=f"JWT signed with wrong key returned {status_code}",
            request={"token": "signed with 'totally_wrong_secret'"},
            response={"status": status_code},
        ))

        # 4. Tampered payload - valid signature but fabricated instance_id
        tampered_payload = self._make_valid_payload(instance_id="hacked_instance")
        tampered_token = self._encode_jwt(tampered_payload)
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": tampered_token},
        )
        results.append(self._make_result(
            variant="tampered_instance_id",
            status=Status.VULNERABLE if status_code == 200 else Status.DEFENDED,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=(
                f"JWT with fabricated instance_id returned {status_code}. "
                "If 200, attacker can access arbitrary tenant data."
            ),
            request={"token": "instance_id='hacked_instance'"},
            response={"status": status_code, "body": body[:200]},
        ))

        # 5. "none" algorithm attack - JWT with alg=none
        try:
            none_token = pyjwt.encode(
                self._make_valid_payload(), "", algorithm="none",
            )
        except Exception:
            # Fallback: manually construct alg=none token
            import base64
            import json as _json
            header = base64.urlsafe_b64encode(
                _json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            payload_b64 = base64.urlsafe_b64encode(
                _json.dumps(self._make_valid_payload()).encode()
            ).rstrip(b"=").decode()
            none_token = f"{header}.{payload_b64}."
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": none_token},
        )
        results.append(self._make_result(
            variant="none_algorithm",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=f"JWT with alg=none returned {status_code}",
            request={"token": "alg=none"},
            response={"status": status_code},
        ))

        # 6. Empty cookie value - send empty eqmon_session cookie
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": ""},
        )
        results.append(self._make_result(
            variant="empty_cookie",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            evidence=f"Status: {status_code}",
            details=f"Empty cookie returned {status_code}",
            request={"token": "empty string"},
            response={"status": status_code},
        ))

        # 7. Malformed JWT - send "not.a.jwt.token" as cookie
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": "not.a.valid.jwt.token"},
        )
        results.append(self._make_result(
            variant="malformed_jwt",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=f"Malformed JWT returned {status_code}",
            request={"token": "not.a.valid.jwt.token"},
            response={"status": status_code},
        ))

        return results
```

---

## redteam/attacks/api/idor.py

Tests Insecure Direct Object Reference -- cross-user and cross-tenant data access:
1. Access another user's chat history by guessing session_id
2. Access another user's analysis chat by analysis_id
3. Read bearing notes for a device the user shouldn't access
4. Delete another user's bearing note by ID
5. Write a bearing note to another instance's device

```python
"""Insecure Direct Object Reference (IDOR) attacks - cross-user/cross-tenant data access."""

import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class IdorAttack(Attack):
    name = "api.idor"
    category = "api"
    severity = Severity.HIGH
    description = "Cross-user and cross-tenant data access via IDOR"

    # These IDs belong to "another user" -- we should NOT be able to access them
    OTHER_USER_SESSION_ID = "other-user-session-00001"
    OTHER_USER_ANALYSIS_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    OTHER_USER_NOTE_ID = 999999  # A note ID that doesn't belong to the test user
    OTHER_INSTANCE_DEVICE_ID = "other-instance-device-001"

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"

        # 1. Access another user's chat history by guessing session_id
        # The authenticated user should only see their own sessions.
        status_code, body, headers = await client.get(
            test_path,
            params={"session_id": self.OTHER_USER_SESSION_ID},
        )
        # If we get 200 with actual messages, it's an IDOR vulnerability.
        # If we get 200 with empty array, it's likely just "no data" (defended).
        # If we get 403/404, it's explicitly defended.
        has_messages = '"messages"' in body and body.count('"message"') > 0
        if status_code == 200 and has_messages:
            idor_status = Status.VULNERABLE
        elif status_code in (403, 404, 401):
            idor_status = Status.DEFENDED
        else:
            # 200 with empty data -- no explicit access control, but no data leaked
            idor_status = Status.PARTIAL
        results.append(self._make_result(
            variant="other_user_session_id",
            status=idor_status,
            evidence=f"Status: {status_code}, Body length: {len(body)}, Has messages: {has_messages}",
            details=(
                f"Attempted to access session_id='{self.OTHER_USER_SESSION_ID}' "
                f"belonging to another user. Got {status_code}."
            ),
            request={"session_id": self.OTHER_USER_SESSION_ID},
            response={"status": status_code, "body": body[:300]},
        ))

        # 2. Access another user's analysis chat by analysis_id
        status_code, body, headers = await client.get(
            test_path,
            params={"analysis_id": self.OTHER_USER_ANALYSIS_ID},
        )
        has_messages = '"messages"' in body and body.count('"message"') > 0
        if status_code == 200 and has_messages:
            idor_status = Status.VULNERABLE
        elif status_code in (403, 404, 401):
            idor_status = Status.DEFENDED
        else:
            idor_status = Status.PARTIAL
        results.append(self._make_result(
            variant="other_user_analysis_id",
            status=idor_status,
            evidence=f"Status: {status_code}, Body length: {len(body)}, Has messages: {has_messages}",
            details=(
                f"Attempted to access analysis_id='{self.OTHER_USER_ANALYSIS_ID}' "
                f"belonging to another user. Got {status_code}."
            ),
            request={"analysis_id": self.OTHER_USER_ANALYSIS_ID},
            response={"status": status_code, "body": body[:300]},
        ))

        # 3. Read bearing notes for a device the user shouldn't access
        # Try to fetch notes by posting with a device_id from a different tenant
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "get_notes",
                "device_id": self.OTHER_INSTANCE_DEVICE_ID,
            },
        )
        has_notes = '"notes"' in body and len(body) > 50
        if status_code == 200 and has_notes:
            idor_status = Status.VULNERABLE
        elif status_code in (403, 404, 401):
            idor_status = Status.DEFENDED
        else:
            idor_status = Status.PARTIAL
        results.append(self._make_result(
            variant="other_tenant_device_notes",
            status=idor_status,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Attempted to read notes for device_id='{self.OTHER_INSTANCE_DEVICE_ID}' "
                f"from another tenant. Got {status_code}."
            ),
            request={"action": "get_notes", "device_id": self.OTHER_INSTANCE_DEVICE_ID},
            response={"status": status_code, "body": body[:300]},
        ))

        # 4. Delete another user's bearing note by ID
        status_code, body, headers = await client.delete(
            test_path,
            params={"action": "delete_note", "id": str(self.OTHER_USER_NOTE_ID)},
        )
        # Success = vulnerability (we deleted someone else's note)
        if status_code == 200 and ("success" in body.lower() or "deleted" in body.lower()):
            idor_status = Status.VULNERABLE
        elif status_code in (403, 404, 401):
            idor_status = Status.DEFENDED
        else:
            # Could be 200 with error message, or 500
            idor_status = Status.PARTIAL
        results.append(self._make_result(
            variant="delete_other_user_note",
            status=idor_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Attempted to delete note id={self.OTHER_USER_NOTE_ID} "
                f"belonging to another user. Got {status_code}."
            ),
            request={"action": "delete_note", "id": self.OTHER_USER_NOTE_ID},
            response={"status": status_code, "body": body[:300]},
        ))

        # 5. Write a bearing note to another instance's device
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "add_note",
                "device_id": self.OTHER_INSTANCE_DEVICE_ID,
                "note": "REDTEAM-IDOR-TEST: This note should not be writable",
            },
        )
        if status_code == 200 and ("success" in body.lower() or '"id"' in body):
            idor_status = Status.VULNERABLE
        elif status_code in (403, 404, 401):
            idor_status = Status.DEFENDED
        else:
            idor_status = Status.PARTIAL
        results.append(self._make_result(
            variant="write_note_other_instance",
            status=idor_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Attempted to write a note to device_id='{self.OTHER_INSTANCE_DEVICE_ID}' "
                f"in another instance. Got {status_code}."
            ),
            request={
                "action": "add_note",
                "device_id": self.OTHER_INSTANCE_DEVICE_ID,
                "note": "REDTEAM-IDOR-TEST...",
            },
            response={"status": status_code, "body": body[:300]},
        ))

        return results

    async def cleanup(self, client) -> None:
        """Attempt to clean up any notes we may have created during IDOR testing."""
        # If variant 5 succeeded (vulnerable), we created a note that should be removed.
        # We can't easily know the ID, so this is best-effort.
        pass
```

---

## redteam/attacks/api/authz_boundaries.py

Tests role escalation and company/vessel boundary enforcement:
1. Viewer attempting to add a note (write operation)
2. Viewer attempting to send a chat message
3. Cross-company: JWT with different opco_id
4. Cross-vessel: JWT with different vessel_id
5. Role escalation: JWT with elevated role (viewer -> system-admin)

```python
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
            "email": f"redteam-authz-{role}@test.com",
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
```

---

## redteam/attacks/api/injection.py

SQL injection tests against all user-controllable parameters:
1. analysis_id parameter with DROP TABLE
2. session_id parameter with OR tautology
3. device_id in notes with UNION SELECT
4. message body with SQL
5. GET parameter with comment-based injection
6. Boolean blind injection

```python
"""SQL injection attacks against EQMON API parameters."""

import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class InjectionAttack(Attack):
    name = "api.injection"
    category = "api"
    severity = Severity.CRITICAL
    description = "SQL injection via user-controllable API parameters"

    # Common SQL injection payloads
    PAYLOADS = {
        "drop_table": "'; DROP TABLE ai_chat_messages; --",
        "or_tautology": "' OR '1'='1",
        "union_select": "' UNION SELECT password_hash FROM users --",
        "stacked_query": "'; SELECT * FROM users; --",
        "comment_bypass": "' OR 1=1 --",
        "boolean_blind": "' AND 1=1 --",
    }

    def _check_sqli_indicators(self, body: str) -> list[str]:
        """Check response body for signs of SQL injection success or error disclosure."""
        indicators = []
        sqli_signatures = [
            ("sql", "SQL keyword found in response"),
            ("syntax error", "SQL syntax error disclosed"),
            ("mysql", "MySQL reference in response"),
            ("postgresql", "PostgreSQL reference in response"),
            ("pdo", "PDO reference in response"),
            ("ORA-", "Oracle error in response"),
            ("SQLSTATE", "SQLSTATE error code in response"),
            ("password_hash", "Password hash column name leaked"),
            ("pg_catalog", "PostgreSQL catalog reference leaked"),
            ("information_schema", "Database schema reference leaked"),
            ("table", "Table reference in error message"),
        ]
        body_lower = body.lower()
        for keyword, desc in sqli_signatures:
            if keyword.lower() in body_lower:
                indicators.append(desc)
        return indicators

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"

        # 1. analysis_id parameter: '; DROP TABLE ai_chat_messages; --
        payload = self.PAYLOADS["drop_table"]
        status_code, body, headers = await client.get(
            test_path,
            params={"analysis_id": payload},
        )
        indicators = self._check_sqli_indicators(body)
        # If server returns 200 or leaks SQL details, it's vulnerable
        if indicators:
            sqli_status = Status.VULNERABLE
        elif status_code == 500:
            # Server error might mean the injection reached the DB but failed
            sqli_status = Status.PARTIAL
        elif status_code in (400, 422):
            sqli_status = Status.DEFENDED
        else:
            sqli_status = Status.PARTIAL
        results.append(self._make_result(
            variant="analysis_id_drop_table",
            status=sqli_status,
            evidence=f"Status: {status_code}, Indicators: {indicators}, Body: {body[:300]}",
            details=(
                f"Injected DROP TABLE via analysis_id parameter. "
                f"Status: {status_code}. SQL indicators: {indicators or 'none'}."
            ),
            request={"param": "analysis_id", "payload": payload},
            response={"status": status_code, "body": body[:300]},
        ))

        # 2. session_id parameter: ' OR '1'='1
        payload = self.PAYLOADS["or_tautology"]
        status_code, body, headers = await client.get(
            test_path,
            params={"session_id": payload},
        )
        indicators = self._check_sqli_indicators(body)
        # If tautology returns other users' data, it's a clear vulnerability
        has_unexpected_data = '"messages"' in body and len(body) > 200
        if has_unexpected_data or indicators:
            sqli_status = Status.VULNERABLE
        elif status_code == 500:
            sqli_status = Status.PARTIAL
        elif status_code in (400, 422):
            sqli_status = Status.DEFENDED
        else:
            sqli_status = Status.DEFENDED
        results.append(self._make_result(
            variant="session_id_or_tautology",
            status=sqli_status,
            evidence=f"Status: {status_code}, Body length: {len(body)}, Indicators: {indicators}",
            details=(
                f"Injected OR tautology via session_id. "
                f"Status: {status_code}, response length: {len(body)}. "
                f"Large response may indicate data leak."
            ),
            request={"param": "session_id", "payload": payload},
            response={"status": status_code, "body": body[:300]},
        ))

        # 3. device_id in notes: ' UNION SELECT password_hash FROM users --
        payload = self.PAYLOADS["union_select"]
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "add_note",
                "device_id": payload,
                "note": "REDTEAM-SQLI-TEST",
            },
        )
        indicators = self._check_sqli_indicators(body)
        if indicators or "password" in body.lower():
            sqli_status = Status.VULNERABLE
        elif status_code == 500:
            sqli_status = Status.PARTIAL
        elif status_code in (400, 422):
            sqli_status = Status.DEFENDED
        else:
            sqli_status = Status.PARTIAL
        results.append(self._make_result(
            variant="device_id_union_select",
            status=sqli_status,
            evidence=f"Status: {status_code}, Indicators: {indicators}, Body: {body[:300]}",
            details=(
                f"Injected UNION SELECT via device_id in add_note. "
                f"Status: {status_code}. Indicators: {indicators or 'none'}."
            ),
            request={"param": "device_id", "payload": payload},
            response={"status": status_code, "body": body[:300]},
        ))

        # 4. message body with SQL: '; SELECT * FROM users; --
        payload = self.PAYLOADS["stacked_query"]
        session_id = f"redteam-sqli-{uuid.uuid4().hex[:8]}"
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "send_message",
                "message": payload,
                "session_id": session_id,
            },
        )
        indicators = self._check_sqli_indicators(body)
        if indicators:
            sqli_status = Status.VULNERABLE
        elif status_code == 500:
            sqli_status = Status.PARTIAL
        else:
            # Message body likely gets stored as text, not injected into SQL directly
            sqli_status = Status.DEFENDED
        results.append(self._make_result(
            variant="message_body_stacked_query",
            status=sqli_status,
            severity=Severity.HIGH,
            evidence=f"Status: {status_code}, Indicators: {indicators}, Body: {body[:300]}",
            details=(
                f"Injected stacked SQL query via message body. "
                f"Status: {status_code}. Message content typically parameterized, "
                f"but verifying. Indicators: {indicators or 'none'}."
            ),
            request={"param": "message", "payload": payload},
            response={"status": status_code, "body": body[:300]},
        ))

        # 5. GET parameter: ?analysis_id=' OR 1=1 --
        payload = self.PAYLOADS["comment_bypass"]
        # Append to a real-looking analysis_id
        full_payload = "d381c227-4ae2-442b-bc04-970fecc7ca9e" + payload
        status_code, body, headers = await client.get(
            test_path,
            params={"analysis_id": full_payload},
        )
        indicators = self._check_sqli_indicators(body)
        has_unexpected_data = '"messages"' in body and len(body) > 200
        if has_unexpected_data or indicators:
            sqli_status = Status.VULNERABLE
        elif status_code == 500:
            sqli_status = Status.PARTIAL
        elif status_code in (400, 422):
            sqli_status = Status.DEFENDED
        else:
            sqli_status = Status.DEFENDED
        results.append(self._make_result(
            variant="get_param_comment_bypass",
            status=sqli_status,
            evidence=f"Status: {status_code}, Body length: {len(body)}, Indicators: {indicators}",
            details=(
                f"Injected comment-based bypass via GET analysis_id. "
                f"Status: {status_code}. Indicators: {indicators or 'none'}."
            ),
            request={"param": "analysis_id (GET)", "payload": full_payload},
            response={"status": status_code, "body": body[:300]},
        ))

        # 6. Boolean blind: ?analysis_id=<valid_id>' AND 1=1 --
        # Compare response of AND 1=1 vs AND 1=2 to detect blind SQLi
        base_id = "d381c227-4ae2-442b-bc04-970fecc7ca9e"

        true_payload = base_id + "' AND 1=1 --"
        status_true, body_true, _ = await client.get(
            test_path,
            params={"analysis_id": true_payload},
        )

        false_payload = base_id + "' AND 1=2 --"
        status_false, body_false, _ = await client.get(
            test_path,
            params={"analysis_id": false_payload},
        )

        indicators_true = self._check_sqli_indicators(body_true)
        indicators_false = self._check_sqli_indicators(body_false)

        # If the two responses differ meaningfully, blind SQLi is likely
        responses_differ = (
            len(body_true) != len(body_false)
            or status_true != status_false
        )
        if responses_differ and not indicators_true and not indicators_false:
            sqli_status = Status.VULNERABLE
            detail_note = "Responses differ between AND 1=1 and AND 1=2 -- blind SQLi likely."
        elif indicators_true or indicators_false:
            sqli_status = Status.VULNERABLE
            detail_note = f"SQL indicators found. True: {indicators_true}, False: {indicators_false}."
        else:
            sqli_status = Status.DEFENDED
            detail_note = "Responses identical for both payloads -- input likely parameterized."
        results.append(self._make_result(
            variant="boolean_blind_sqli",
            status=sqli_status,
            evidence=(
                f"True: status={status_true}, len={len(body_true)}; "
                f"False: status={status_false}, len={len(body_false)}"
            ),
            details=f"Boolean blind SQLi test. {detail_note}",
            request={
                "true_payload": true_payload,
                "false_payload": false_payload,
            },
            response={
                "true_status": status_true,
                "true_body": body_true[:200],
                "false_status": status_false,
                "false_body": body_false[:200],
            },
        ))

        return results

    async def cleanup(self, client) -> None:
        """No persistent artifacts from injection tests (payloads are read-oriented)."""
        pass
```

---

## redteam/attacks/api/input_validation.py

Tests how the API handles malformed, oversized, and type-confused input:
1. Oversized message (1MB)
2. Null bytes embedded in message
3. Unicode control characters (RTL override, zero-width)
4. Empty JSON body
5. Malformed JSON (not valid JSON at all)
6. Wrong types (number for message, boolean for session_id)

```python
"""Input validation attacks - malformed, oversized, and type-confused inputs."""

import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class InputValidationAttack(Attack):
    name = "api.input_validation"
    category = "api"
    severity = Severity.MEDIUM
    description = "Malformed input handling: oversized payloads, null bytes, type confusion"

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"
        session_id = f"redteam-input-{uuid.uuid4().hex[:8]}"

        # 1. Oversized message: 1MB of "A" characters
        oversized_message = "A" * (1024 * 1024)  # 1MB
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "send_message",
                "message": oversized_message,
                "session_id": session_id,
            },
        )
        # Server should reject with 413 or 400, not accept and process 1MB
        if status_code in (413, 400, 422):
            val_status = Status.DEFENDED
        elif status_code == 200:
            val_status = Status.VULNERABLE
        elif status_code == 500:
            val_status = Status.PARTIAL  # Server crashed but at least didn't accept
        else:
            val_status = Status.PARTIAL
        results.append(self._make_result(
            variant="oversized_message_1mb",
            status=val_status,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Sent 1MB message ({len(oversized_message)} chars). "
                f"Got {status_code}. Server should reject with 413 or 400."
            ),
            request={"message_size": f"{len(oversized_message)} chars (1MB)"},
            response={"status": status_code, "body": body[:300]},
        ))

        # 2. Null bytes: message with \x00 embedded
        null_message = "Hello\x00World\x00INJECTED"
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "send_message",
                "message": null_message,
                "session_id": session_id,
            },
        )
        # Null bytes can truncate strings in C-backed systems or cause DB issues
        if status_code in (400, 422):
            val_status = Status.DEFENDED
        elif status_code == 200:
            # Accepted -- check if the null bytes were preserved or stripped
            val_status = Status.PARTIAL  # Not necessarily dangerous, but worth noting
        elif status_code == 500:
            val_status = Status.VULNERABLE  # Null byte caused a crash
        else:
            val_status = Status.PARTIAL
        results.append(self._make_result(
            variant="null_bytes_in_message",
            status=val_status,
            severity=Severity.LOW,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Sent message with embedded null bytes (\\x00). "
                f"Got {status_code}. Null bytes can cause string truncation or DB errors."
            ),
            request={"message": repr(null_message)},
            response={"status": status_code, "body": body[:300]},
        ))

        # 3. Unicode control characters: RTL override, zero-width chars
        # These can be used for text spoofing / visual attacks
        unicode_message = (
            "Normal text "
            "\u202e"  # RTL override -- reverses text direction
            "HIDDEN REVERSED TEXT"
            "\u202c"  # Pop directional formatting
            "\u200b"  # Zero-width space
            "\u200d"  # Zero-width joiner
            "\ufeff"  # BOM / zero-width no-break space
            " end of message"
        )
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "send_message",
                "message": unicode_message,
                "session_id": session_id,
            },
        )
        if status_code in (400, 422):
            val_status = Status.DEFENDED
        elif status_code == 200:
            val_status = Status.PARTIAL  # Accepted -- may enable text spoofing in UI
        elif status_code == 500:
            val_status = Status.VULNERABLE
        else:
            val_status = Status.PARTIAL
        results.append(self._make_result(
            variant="unicode_control_chars",
            status=val_status,
            severity=Severity.LOW,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Sent message with Unicode control characters "
                f"(RTL override U+202E, zero-width space U+200B, BOM U+FEFF). "
                f"Got {status_code}. These can enable text spoofing in UI."
            ),
            request={"message": repr(unicode_message)},
            response={"status": status_code, "body": body[:300]},
        ))

        # 4. Empty JSON body: POST with {}
        status_code, body, headers = await client.post(
            test_path,
            json_body={},
        )
        if status_code in (400, 422):
            val_status = Status.DEFENDED
        elif status_code == 500:
            val_status = Status.VULNERABLE  # Empty body caused a crash
        elif status_code == 200:
            val_status = Status.PARTIAL  # Accepted empty body without error
        else:
            val_status = Status.PARTIAL
        results.append(self._make_result(
            variant="empty_json_body",
            status=val_status,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Sent POST with empty JSON body {{}}. "
                f"Got {status_code}. Server should return 400 for missing required fields."
            ),
            request={"body": "{}"},
            response={"status": status_code, "body": body[:300]},
        ))

        # 5. Malformed JSON: POST with {not valid json
        status_code, body, headers = await client.post(
            test_path,
            raw_body="{not valid json at all",
        )
        if status_code in (400, 422):
            val_status = Status.DEFENDED
        elif status_code == 500:
            val_status = Status.VULNERABLE  # Malformed JSON caused a crash
        elif status_code == 200:
            val_status = Status.VULNERABLE  # Server accepted invalid JSON
        else:
            val_status = Status.PARTIAL
        results.append(self._make_result(
            variant="malformed_json",
            status=val_status,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Sent POST with malformed JSON body. "
                f"Got {status_code}. Server should return 400 for unparseable JSON."
            ),
            request={"body": "{not valid json at all"},
            response={"status": status_code, "body": body[:300]},
        ))

        # 6. Wrong types: number for message, boolean for session_id
        status_code, body, headers = await client.post(
            test_path,
            json_body={
                "action": "send_message",
                "message": 12345,
                "session_id": True,
            },
        )
        if status_code in (400, 422):
            val_status = Status.DEFENDED
        elif status_code == 500:
            val_status = Status.VULNERABLE  # Type confusion caused a crash
        elif status_code == 200:
            val_status = Status.PARTIAL  # Server accepted wrong types (PHP is loose)
        else:
            val_status = Status.PARTIAL
        results.append(self._make_result(
            variant="wrong_types",
            status=val_status,
            severity=Severity.LOW,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=(
                f"Sent message=12345 (int), session_id=true (bool). "
                f"Got {status_code}. Server should validate input types."
            ),
            request={"message": 12345, "session_id": True},
            response={"status": status_code, "body": body[:300]},
        ))

        return results
```

---

## redteam/attacks/api/rate_limiting.py

Tests whether the API enforces rate limiting:
1. Rapid-fire: 50 GET requests in quick succession
2. Concurrent SSE: open 10 simultaneous chat POST requests
3. Note spam: create 100 notes rapidly

```python
"""Rate limiting attacks - flood testing against API endpoints."""

import asyncio
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class RateLimitingAttack(Attack):
    name = "api.rate_limiting"
    category = "api"
    severity = Severity.MEDIUM
    description = "Rate limiting and flood protection tests"

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"

        # 1. Rapid-fire: 50 GET requests in quick succession
        session_id = f"redteam-ratelimit-{uuid.uuid4().hex[:8]}"
        num_requests = 50
        start = time.monotonic()
        statuses = []

        for i in range(num_requests):
            status_code, body, headers = await client.get(
                test_path,
                params={"session_id": f"{session_id}-{i}"},
            )
            statuses.append(status_code)

        elapsed = time.monotonic() - start
        rate_limited = any(s == 429 for s in statuses)
        all_succeeded = all(s in (200, 204, 404) for s in statuses)

        if rate_limited:
            rl_status = Status.DEFENDED
            first_429 = statuses.index(429)
            detail = f"Rate limited after {first_429} requests. First 429 at request #{first_429 + 1}."
        elif all_succeeded:
            rl_status = Status.VULNERABLE
            detail = f"All {num_requests} rapid requests succeeded in {elapsed:.1f}s. No rate limiting detected."
        else:
            rl_status = Status.PARTIAL
            detail = f"Mixed responses (no 429). Statuses: {set(statuses)}."
        results.append(self._make_result(
            variant="rapid_fire_50_gets",
            status=rl_status,
            evidence=(
                f"Sent {num_requests} requests in {elapsed:.1f}s. "
                f"429 count: {statuses.count(429)}, "
                f"200 count: {statuses.count(200)}"
            ),
            details=detail,
            request={"num_requests": num_requests, "elapsed_sec": round(elapsed, 2)},
            response={"status_distribution": {str(s): statuses.count(s) for s in set(statuses)}},
        ))

        # 2. Concurrent SSE: 10 simultaneous chat POST requests
        # Opening many concurrent SSE streams can exhaust server resources.
        num_concurrent = 10

        async def _send_chat(idx: int) -> tuple[int, float]:
            """Send a chat request and return (status_code, duration_ms)."""
            s_id = f"redteam-concurrent-{uuid.uuid4().hex[:8]}"
            req_start = time.monotonic()
            try:
                status_code, body, headers = await client.post(
                    test_path,
                    json_body={
                        "action": "send_message",
                        "message": f"Concurrent test #{idx}",
                        "session_id": s_id,
                    },
                )
                duration = (time.monotonic() - req_start) * 1000
                return status_code, duration
            except Exception:
                duration = (time.monotonic() - req_start) * 1000
                return 0, duration

        start = time.monotonic()
        tasks = [_send_chat(i) for i in range(num_concurrent)]
        concurrent_results = await asyncio.gather(*tasks)
        elapsed = time.monotonic() - start

        concurrent_statuses = [r[0] for r in concurrent_results]
        rate_limited = any(s == 429 for s in concurrent_statuses)
        all_succeeded = all(s in (200, 204) for s in concurrent_statuses)
        errors = sum(1 for s in concurrent_statuses if s >= 500 or s == 0)

        if rate_limited:
            rl_status = Status.DEFENDED
            detail = f"Rate limited under concurrent load. 429 count: {concurrent_statuses.count(429)}."
        elif all_succeeded:
            rl_status = Status.VULNERABLE
            detail = (
                f"All {num_concurrent} concurrent SSE streams accepted in {elapsed:.1f}s. "
                "No concurrency limiting detected."
            )
        elif errors > 0:
            rl_status = Status.PARTIAL
            detail = (
                f"{errors} errors under concurrent load. "
                "Server may be overwhelmed but doesn't explicitly rate limit."
            )
        else:
            rl_status = Status.PARTIAL
            detail = f"Mixed responses under concurrent load. Statuses: {set(concurrent_statuses)}."
        results.append(self._make_result(
            variant="concurrent_sse_10_streams",
            status=rl_status,
            evidence=(
                f"Sent {num_concurrent} concurrent requests in {elapsed:.1f}s. "
                f"Statuses: {concurrent_statuses}"
            ),
            details=detail,
            request={"num_concurrent": num_concurrent, "elapsed_sec": round(elapsed, 2)},
            response={
                "status_distribution": {
                    str(s): concurrent_statuses.count(s) for s in set(concurrent_statuses)
                },
            },
        ))

        # 3. Note spam: create 100 notes rapidly
        num_notes = 100
        device_id = f"redteam-ratelimit-device-{uuid.uuid4().hex[:8]}"
        start = time.monotonic()
        note_statuses = []
        created_note_ids = []

        for i in range(num_notes):
            status_code, body, headers = await client.post(
                test_path,
                json_body={
                    "action": "add_note",
                    "device_id": device_id,
                    "note": f"REDTEAM-SPAM-NOTE-{i:04d}",
                },
            )
            note_statuses.append(status_code)
            # Track created note IDs for cleanup
            if status_code == 200 and '"id"' in body:
                try:
                    import json
                    resp_data = json.loads(body)
                    if "id" in resp_data:
                        created_note_ids.append(resp_data["id"])
                except Exception:
                    pass

        elapsed = time.monotonic() - start
        rate_limited = any(s == 429 for s in note_statuses)
        all_succeeded = all(s in (200, 201) for s in note_statuses)

        if rate_limited:
            rl_status = Status.DEFENDED
            first_429 = note_statuses.index(429)
            detail = f"Rate limited after {first_429} notes. First 429 at note #{first_429 + 1}."
        elif all_succeeded:
            rl_status = Status.VULNERABLE
            detail = (
                f"All {num_notes} notes created in {elapsed:.1f}s "
                f"({num_notes / elapsed:.1f} notes/sec). No rate limiting."
            )
        else:
            rl_status = Status.PARTIAL
            detail = f"Mixed responses during note spam. Statuses: {set(note_statuses)}."
        results.append(self._make_result(
            variant="note_spam_100",
            status=rl_status,
            evidence=(
                f"Created {note_statuses.count(200)} of {num_notes} notes in {elapsed:.1f}s. "
                f"429 count: {note_statuses.count(429)}"
            ),
            details=detail,
            request={
                "num_notes": num_notes,
                "device_id": device_id,
                "elapsed_sec": round(elapsed, 2),
            },
            response={"status_distribution": {str(s): note_statuses.count(s) for s in set(note_statuses)}},
        ))

        # Store cleanup data for later
        self._cleanup_device_id = device_id
        self._cleanup_note_ids = created_note_ids

        return results

    async def cleanup(self, client) -> None:
        """Delete spam notes created during rate limiting tests."""
        test_path = "/api/ai_chat.php"
        for note_id in getattr(self, "_cleanup_note_ids", []):
            try:
                await client.delete(
                    test_path,
                    params={"action": "delete_note", "id": str(note_id)},
                )
            except Exception:
                pass
```

---

## redteam/attacks/api/error_leakage.py

Tests whether the API leaks internal implementation details in error responses:
1. Trigger PDOException with invalid analysis_id format
2. Trigger type error with unexpected data types
3. Check for stack traces in error responses
4. Check for file paths, DB names, table names in errors

```python
"""Error information leakage attacks - testing for exposed internal details."""

import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class ErrorLeakageAttack(Attack):
    name = "api.error_leakage"
    category = "api"
    severity = Severity.MEDIUM
    description = "Information disclosure via error messages and stack traces"

    # Keywords that indicate internal implementation details are leaking
    LEAKAGE_KEYWORDS = {
        # Database internals
        "PDOException": "PDO exception class name exposed",
        "SQLSTATE": "SQL state error code exposed",
        "pg_query": "PostgreSQL function name exposed",
        "pg_connect": "PostgreSQL connection function exposed",
        "mysql_": "MySQL function reference exposed",
        "pgsql": "PostgreSQL reference exposed",

        # Stack traces
        "Stack trace": "Full stack trace exposed",
        "Traceback": "Python-style traceback exposed",
        "#0 ": "PHP stack trace frame exposed",
        "at line": "Error line number exposed",
        "on line": "Error line number exposed",

        # File paths
        "/var/www": "Server file path exposed",
        "/opt/": "Server file path exposed",
        "/home/": "Server home directory exposed",
        ".php on line": "PHP file path and line exposed",

        # Database schema
        "ai_chat_messages": "Database table name exposed",
        "bearing_notes": "Database table name exposed",
        "users": "Users table name exposed (context-dependent)",
        "eqmon": "Database name exposed",

        # Configuration
        "password": "Password reference in error",
        "secret": "Secret reference in error",
        "api_key": "API key reference in error",

        # Server internals
        "X-Powered-By": "Server technology header exposed",
        "PHP/": "PHP version exposed",
        "nginx": "Web server identity exposed",
        "Apache": "Web server identity exposed",
    }

    def _scan_for_leakage(self, body: str, headers: dict) -> list[str]:
        """Scan response body and headers for information leakage indicators."""
        findings = []
        # Scan body
        for keyword, description in self.LEAKAGE_KEYWORDS.items():
            if keyword.lower() in body.lower():
                findings.append(f"BODY: {description} (matched '{keyword}')")
        # Scan headers
        combined_headers = " ".join(f"{k}: {v}" for k, v in headers.items())
        for keyword, description in self.LEAKAGE_KEYWORDS.items():
            if keyword.lower() in combined_headers.lower():
                findings.append(f"HEADER: {description} (matched '{keyword}')")
        return findings

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"

        # 1. Trigger PDOException: send analysis_id with format that breaks SQL
        # A single quote should cause a SQL parsing error if not parameterized.
        # Even if parameterized, a wildly invalid UUID format may trigger validation errors.
        bad_payloads = [
            "' ; --",
            "not-a-uuid-at-all-!@#$%^&*()",
            "\x00\x01\x02\x03",
            "a" * 10000,
        ]
        worst_findings = []
        worst_body = ""
        worst_status = 0

        for payload in bad_payloads:
            status_code, body, headers = await client.get(
                test_path,
                params={"analysis_id": payload},
            )
            findings = self._scan_for_leakage(body, headers)
            if len(findings) > len(worst_findings):
                worst_findings = findings
                worst_body = body
                worst_status = status_code

        if worst_findings:
            leak_status = Status.VULNERABLE
            # Determine severity based on what leaked
            has_stack_trace = any("stack trace" in f.lower() or "traceback" in f.lower() for f in worst_findings)
            has_file_path = any("file path" in f.lower() for f in worst_findings)
            has_db_details = any("table name" in f.lower() or "database" in f.lower() for f in worst_findings)
            if has_stack_trace or has_file_path:
                leak_severity = Severity.HIGH
            elif has_db_details:
                leak_severity = Severity.MEDIUM
            else:
                leak_severity = Severity.MEDIUM
        else:
            leak_status = Status.DEFENDED
            leak_severity = None
        results.append(self._make_result(
            variant="trigger_pdo_exception",
            status=leak_status,
            severity=leak_severity,
            evidence=f"Findings: {worst_findings}, Status: {worst_status}, Body: {worst_body[:500]}",
            details=(
                f"Sent malformed analysis_id values to trigger database errors. "
                f"Found {len(worst_findings)} leakage indicators. "
                f"{'Details: ' + '; '.join(worst_findings[:5]) if worst_findings else 'No leakage detected.'}"
            ),
            request={"payloads": [p[:50] for p in bad_payloads]},
            response={"status": worst_status, "body": worst_body[:500]},
        ))

        # 2. Trigger type error: send unexpected data structures
        type_error_payloads = [
            {"action": ["send_message"], "message": {"nested": "object"}, "session_id": 42},
            {"action": None},
            {"action": "send_message", "message": ["array", "of", "strings"]},
        ]

        worst_findings = []
        worst_body = ""
        worst_status = 0

        for payload in type_error_payloads:
            status_code, body, headers = await client.post(
                test_path,
                json_body=payload,
            )
            findings = self._scan_for_leakage(body, headers)
            if len(findings) > len(worst_findings):
                worst_findings = findings
                worst_body = body
                worst_status = status_code

        if worst_findings:
            leak_status = Status.VULNERABLE
        else:
            leak_status = Status.DEFENDED
        results.append(self._make_result(
            variant="trigger_type_error",
            status=leak_status,
            evidence=f"Findings: {worst_findings}, Status: {worst_status}, Body: {worst_body[:500]}",
            details=(
                f"Sent payloads with wrong types (arrays, objects, null, numbers) "
                f"to trigger type errors. "
                f"Found {len(worst_findings)} leakage indicators. "
                f"{'Details: ' + '; '.join(worst_findings[:5]) if worst_findings else 'No leakage detected.'}"
            ),
            request={"payloads": [str(p)[:100] for p in type_error_payloads]},
            response={"status": worst_status, "body": worst_body[:500]},
        ))

        # 3. Check for stack traces in error responses
        # Trigger various error conditions and check specifically for stack trace patterns
        error_triggers = [
            # Missing required fields
            ({"action": "delete_note"}, "POST"),
            # Invalid action
            ({"action": "nonexistent_action_12345"}, "POST"),
            # Very long action name
            ({"action": "A" * 10000}, "POST"),
        ]

        stack_trace_patterns = [
            "#0 ",  # PHP stack trace
            "Stack trace:",
            "Traceback (most recent",
            "at /",
            "in /var/www",
            "Fatal error:",
            "Warning:",
            "Notice:",
        ]

        found_stack_traces = []
        worst_body = ""
        worst_status = 0

        for payload, method in error_triggers:
            if method == "POST":
                status_code, body, headers = await client.post(test_path, json_body=payload)
            else:
                status_code, body, headers = await client.get(test_path, params=payload)
            for pattern in stack_trace_patterns:
                if pattern.lower() in body.lower():
                    found_stack_traces.append(f"Found '{pattern}' in response to {payload}")
                    if len(body) > len(worst_body):
                        worst_body = body
                        worst_status = status_code

        if found_stack_traces:
            leak_status = Status.VULNERABLE
            leak_severity = Severity.HIGH
        else:
            leak_status = Status.DEFENDED
            leak_severity = None
        results.append(self._make_result(
            variant="stack_traces_in_errors",
            status=leak_status,
            severity=leak_severity,
            evidence=f"Stack traces found: {found_stack_traces}, Body: {worst_body[:500]}",
            details=(
                f"Triggered {len(error_triggers)} error conditions and checked for "
                f"stack trace patterns. "
                f"Found {len(found_stack_traces)} stack trace occurrences. "
                f"{'Details: ' + '; '.join(found_stack_traces[:3]) if found_stack_traces else 'No stack traces detected.'}"
            ),
            request={"triggers": [str(t[0])[:80] for t in error_triggers]},
            response={"status": worst_status, "body": worst_body[:500]},
        ))

        # 4. Check for file paths, DB names, table names in standard error responses
        # Make requests that are likely to produce error responses and scan all of them.
        probe_requests = [
            ("GET", {"analysis_id": "invalid"}),
            ("GET", {"session_id": ""}),
            ("POST", {"action": "send_message"}),  # Missing message field
            ("DELETE", {"action": "delete_note", "id": "not_a_number"}),
            ("POST", {"action": "add_note"}),  # Missing device_id and note
        ]

        all_findings = []
        worst_body = ""
        worst_status = 0

        for method, params_or_body in probe_requests:
            if method == "GET":
                status_code, body, headers = await client.get(test_path, params=params_or_body)
            elif method == "POST":
                status_code, body, headers = await client.post(test_path, json_body=params_or_body)
            elif method == "DELETE":
                status_code, body, headers = await client.delete(test_path, params=params_or_body)
            else:
                continue

            findings = self._scan_for_leakage(body, headers)
            for f in findings:
                if f not in all_findings:
                    all_findings.append(f)
            if len(findings) > 0 and len(body) > len(worst_body):
                worst_body = body
                worst_status = status_code

        if all_findings:
            leak_status = Status.VULNERABLE
            # Categorize severity
            has_critical = any(
                kw in " ".join(all_findings).lower()
                for kw in ["password", "secret", "api_key", "stack trace"]
            )
            leak_severity = Severity.HIGH if has_critical else Severity.MEDIUM
        else:
            leak_status = Status.DEFENDED
            leak_severity = None
        results.append(self._make_result(
            variant="internal_details_in_errors",
            status=leak_status,
            severity=leak_severity,
            evidence=f"Total findings: {len(all_findings)}, Details: {all_findings[:10]}",
            details=(
                f"Sent {len(probe_requests)} probe requests to trigger error conditions. "
                f"Scanned all responses for file paths, DB names, table names, and server info. "
                f"Found {len(all_findings)} unique leakage indicators. "
                f"{'Indicators: ' + '; '.join(all_findings[:5]) if all_findings else 'No internal details leaked.'}"
            ),
            request={"probes": [f"{m} {str(p)[:60]}" for m, p in probe_requests]},
            response={"status": worst_status, "body": worst_body[:500]},
        ))

        return results
```

---

## Steps

1. Write `redteam/attacks/api/auth_bypass.py`
2. Write `redteam/attacks/api/idor.py`
3. Write `redteam/attacks/api/authz_boundaries.py`
4. Write `redteam/attacks/api/injection.py`
5. Write `redteam/attacks/api/input_validation.py`
6. Write `redteam/attacks/api/rate_limiting.py`
7. Write `redteam/attacks/api/error_leakage.py`
8. Run: `python -c "from redteam.attacks.api.auth_bypass import AuthBypassAttack; print('OK')"` (repeat for each module)
9. Run: `python -m pytest tests/ -v` -- ensure no regressions
10. Commit: `git add -A && git commit -m "feat: API security attack modules - auth, IDOR, authz, SQLi, input validation, rate limiting, error leakage"`

## Acceptance Criteria

- [ ] All 7 attack modules exist under `redteam/attacks/api/`
- [ ] Each module defines exactly one `Attack` subclass with proper `name`, `category`, `severity`, `description`
- [ ] `auth_bypass.py` has 7 variants covering no-cookie, expired, wrong-key, tampered, none-alg, empty, malformed
- [ ] `idor.py` has 5 variants covering session, analysis, notes read, notes delete, notes write
- [ ] `authz_boundaries.py` has 5 variants covering viewer-write, viewer-chat, cross-company, cross-vessel, role-escalation
- [ ] `injection.py` has 6 variants covering DROP, OR tautology, UNION, stacked, comment, boolean-blind
- [ ] `input_validation.py` has 6 variants covering oversized, null-bytes, unicode, empty-json, malformed-json, wrong-types
- [ ] `rate_limiting.py` has 3 variants covering rapid-fire, concurrent-SSE, note-spam
- [ ] `error_leakage.py` has 4 variants covering PDO-exception, type-error, stack-traces, internal-details
- [ ] All modules import cleanly: `from redteam.attacks.api.<module> import <Class>`
- [ ] `rate_limiting.py` has a `cleanup()` method that deletes spam notes
- [ ] All results use `_make_result()` helper with proper `variant`, `status`, `evidence`, `details`, `request`, `response`
- [ ] Status evaluation logic: `Status.DEFENDED` for expected rejection codes, `Status.VULNERABLE` for unexpected success, `Status.PARTIAL` for ambiguous outcomes
- [ ] No hardcoded credentials beyond the known JWT secret (which is the test target)
- [ ] Changes committed with descriptive message
