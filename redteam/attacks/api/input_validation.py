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
