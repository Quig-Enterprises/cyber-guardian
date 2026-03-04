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
