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
