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
