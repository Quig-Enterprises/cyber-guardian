"""Insecure Direct Object Reference (IDOR) attacks - cross-user/cross-tenant data access."""

import json as json_module
import uuid
from typing import Optional

from redteam.base import Attack, AttackResult, Severity, Status


class IdorAttack(Attack):
    name = "api.idor"
    category = "api"
    severity = Severity.HIGH
    description = "Cross-user and cross-tenant data access via IDOR"

    # These IDs belong to "another user" -- we should NOT be able to access them
    OTHER_USER_SESSION_ID = "other-user-session-00001"
    OTHER_USER_ANALYSIS_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    OTHER_USER_NOTE_ID = 999999  # Fallback: a note ID that likely doesn't exist
    OTHER_INSTANCE_DEVICE_ID = "other-instance-device-001"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._created_note_id: Optional[int] = None

    async def _setup_other_user_note(self, client) -> Optional[int]:
        """Create a test note as a secondary user for IDOR testing."""
        # Get viewer credentials from attack config
        viewer = self._config.get("redteam", {}).get("auth", {}).get("test_users", {}).get("viewer", {})
        email = viewer.get("username", "redteam-viewer@example.com")
        password = viewer.get("password", "RedTeamV!ewer2026!")

        try:
            import aiohttp
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                # Login as the viewer user
                login_url = f"{client.base_url}/api/auth/login.php"
                async with session.post(login_url, json={"email": email, "password": password}) as resp:
                    if resp.status != 200:
                        return None
                    cookies = {c.key: c.value for c in resp.cookies.values()}

                # Create a note owned by the viewer
                note_url = f"{client.base_url}/api/ai_chat.php"
                async with session.post(
                    note_url,
                    json={"action": "add_note", "content": "REDTEAM-IDOR-TEST-NOTE", "device_id": "test-device"},
                    cookies=cookies,
                ) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json()
                            return data.get("id") or data.get("note_id")
                        except Exception:
                            return None
        except Exception:
            return None
        return None

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"

        # Try to create a real test note owned by another user for accurate IDOR testing
        real_note_id = await self._setup_other_user_note(client)
        if real_note_id:
            self._created_note_id = real_note_id
        note_id_to_test = real_note_id if real_note_id else self.OTHER_USER_NOTE_ID
        note_id_source = "real viewer-owned note" if real_note_id else "fallback static ID (may not exist)"

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
            params={"action": "delete_note", "id": str(note_id_to_test)},
        )

        # Parse response to distinguish actual success from access-control failure
        try:
            resp_data = json_module.loads(body)
            success = resp_data.get("success", False)
        except (json_module.JSONDecodeError, AttributeError):
            resp_data = {}
            success = False

        if status_code == 200 and success:
            # Server actually deleted it - true IDOR vulnerability
            idor_status = Status.VULNERABLE
        elif status_code in (403, 401):
            # Explicit access denied - properly defended
            idor_status = Status.DEFENDED
        elif status_code == 404:
            # Not found - resource doesn't exist, can't determine access control
            # 404 is acceptable - it doesn't leak info about existence
            idor_status = Status.DEFENDED
        elif status_code == 200 and not success:
            # Server returned 200 but operation failed - likely ownership check
            error_msg = resp_data.get("error", "") if isinstance(resp_data, dict) else ""
            if any(kw in error_msg.lower() for kw in ("permission", "forbidden", "owner", "unauthorized", "not yours")):
                idor_status = Status.DEFENDED
            else:
                # Non-specific failure - give benefit of doubt if delete actually failed
                idor_status = Status.DEFENDED
        else:
            idor_status = Status.PARTIAL

        results.append(self._make_result(
            variant="delete_other_user_note",
            status=idor_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}, Note source: {note_id_source}",
            details=(
                f"Attempted to delete note id={note_id_to_test} ({note_id_source}) "
                f"belonging to another user. Got {status_code}."
            ),
            request={"action": "delete_note", "id": note_id_to_test},
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
        if self._created_note_id is not None:
            # Try to delete the viewer-owned test note we created during setup.
            # Use viewer credentials to authenticate the deletion.
            viewer = self._config.get("redteam", {}).get("auth", {}).get("test_users", {}).get("viewer", {})
            email = viewer.get("username", "redteam-viewer@example.com")
            password = viewer.get("password", "RedTeamV!ewer2026!")

            try:
                import aiohttp
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    # Login as viewer
                    login_url = f"{client.base_url}/api/auth/login.php"
                    async with session.post(login_url, json={"email": email, "password": password}) as resp:
                        if resp.status != 200:
                            return
                        cookies = {c.key: c.value for c in resp.cookies.values()}

                    # Delete the note we created
                    note_url = f"{client.base_url}/api/ai_chat.php"
                    params = {"action": "delete_note", "id": str(self._created_note_id)}
                    async with session.delete(note_url, params=params, cookies=cookies) as resp:
                        pass  # Best-effort cleanup; ignore result
            except Exception:
                pass  # Best-effort; don't raise from cleanup
