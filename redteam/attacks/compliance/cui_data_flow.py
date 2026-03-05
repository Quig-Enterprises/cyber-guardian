"""CUI data flow protection — NIST SP 800-171 Control 3.1.3.

Verifies that Controlled Unclassified Information (CUI) is protected
during data flow: proper cache-control headers, no CUI leakage in
error responses, and data exports include CUI markings.
"""

import json

from redteam.base import Attack, AttackResult, Severity, Status


class CUIDataFlowAttack(Attack):
    name = "compliance.cui_data_flow"
    category = "compliance"
    severity = Severity.MEDIUM
    description = (
        "NIST 3.1.3 — Verify CUI is protected in transit with proper "
        "cache headers, error handling, and export markings"
    )

    # Endpoints that handle CUI data
    CUI_ENDPOINTS = [
        "/api/ai_chat.php",
        "/api/admin/settings.php",
    ]

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # Authenticate for endpoint access
        login_ok = await client.login(
            "redteam-sysadmin@test.com", "RedTeam$ysAdmin2026!"
        )
        if not login_ok:
            results.append(self._make_result(
                variant="cui_in_cache_headers",
                status=Status.ERROR,
                evidence="Login failed — cannot test CUI data flow.",
                details="Could not authenticate to inspect CUI endpoint headers.",
            ))
            return results

        # ----------------------------------------------------------------
        # 1. Cache-Control headers on CUI endpoints
        # ----------------------------------------------------------------
        cache_issues = []
        all_correct = True

        for endpoint in self.CUI_ENDPOINTS:
            status_code, body, headers = await client.get(endpoint)

            cache_control = ""
            pragma = ""
            for key, val in headers.items():
                if key.lower() == "cache-control":
                    cache_control = val.lower()
                elif key.lower() == "pragma":
                    pragma = val.lower()

            has_no_store = "no-store" in cache_control
            has_no_cache = "no-cache" in cache_control or "no-cache" in pragma
            has_private = "private" in cache_control

            if not has_no_store:
                all_correct = False
                cache_issues.append(
                    f"{endpoint}: Cache-Control='{cache_control}' — missing 'no-store'. "
                    "CUI responses may be cached by intermediaries."
                )
            elif not has_no_cache:
                cache_issues.append(
                    f"{endpoint}: Has no-store but missing no-cache directive."
                )

        if all_correct and not cache_issues:
            cache_status = Status.DEFENDED
            detail = (
                "All CUI endpoints include Cache-Control: no-store. "
                "Responses will not be cached by browsers or intermediaries."
            )
        elif not all_correct:
            cache_status = Status.VULNERABLE
            detail = (
                "CUI endpoints missing Cache-Control: no-store. "
                "Sensitive data may be cached by browsers or proxy servers. "
                "NIST 3.1.3 requires controlling CUI data flow."
            )
        else:
            cache_status = Status.PARTIAL
            detail = "Cache headers partially configured."

        results.append(self._make_result(
            variant="cui_in_cache_headers",
            status=cache_status,
            severity=Severity.MEDIUM,
            evidence="\n".join(cache_issues) if cache_issues else "All endpoints correct",
            details=detail,
            request={"endpoints_checked": self.CUI_ENDPOINTS},
            response={"issues": cache_issues},
        ))

        # ----------------------------------------------------------------
        # 2. CUI leakage in error responses
        # ----------------------------------------------------------------
        error_leaks = []

        # Trigger various error conditions and check for data leakage

        # a) Invalid JSON body
        status_code, body, headers = await client.post(
            "/api/ai_chat.php",
            raw_body="{{invalid json}}",
        )
        if any(indicator in body.lower() for indicator in [
            "stack trace", "sql", "database", "password",
            "secret", "config", "/var/www", "/opt/",
            "pg_connect", "bearer_data", "vessel",
        ]):
            error_leaks.append(
                f"Invalid JSON → status {status_code}: error response contains "
                f"sensitive info. Body preview: {body[:200]}"
            )

        # b) SQL-like injection in parameter to trigger verbose error
        status_code, body, headers = await client.get(
            "/api/ai_chat.php",
            params={"session_id": "' OR 1=1; --"},
        )
        if any(indicator in body.lower() for indicator in [
            "pg_query", "sql", "syntax error", "database",
            "relation", "column", "table",
        ]):
            error_leaks.append(
                f"SQL injection probe → status {status_code}: error exposes "
                f"database details. Body preview: {body[:200]}"
            )

        # c) Non-existent action to trigger error
        status_code, body, headers = await client.post(
            "/api/ai_chat.php",
            json_body={"action": "nonexistent_action_redteam_test"},
        )
        if any(indicator in body.lower() for indicator in [
            "stack trace", "file:", "line:", "/var/www",
            "require", "include", "fatal",
        ]):
            error_leaks.append(
                f"Unknown action → status {status_code}: error exposes "
                f"system paths or stack trace. Body preview: {body[:200]}"
            )

        if error_leaks:
            error_status = Status.VULNERABLE
            detail = (
                f"Found {len(error_leaks)} error response(s) leaking sensitive information. "
                "NIST 3.1.3 requires CUI not be exposed in error conditions."
            )
        else:
            error_status = Status.DEFENDED
            detail = (
                "Error responses do not leak CUI, system paths, or database details. "
                "Error handling properly sanitizes output."
            )

        results.append(self._make_result(
            variant="cui_in_error_responses",
            status=error_status,
            severity=Severity.MEDIUM,
            evidence="\n".join(error_leaks) if error_leaks else "No leaks detected",
            details=detail,
            request={"error_triggers_tested": 3},
            response={"leaks_found": len(error_leaks), "details": error_leaks},
        ))

        # ----------------------------------------------------------------
        # 3. Data export without CUI markings
        # ----------------------------------------------------------------
        # Check if data export endpoints include proper CUI banners/markings
        # Try common export patterns
        export_endpoints = [
            ("/api/ai_chat.php", {"action": "export", "format": "json"}),
            ("/api/ai_chat.php", {"action": "export_chat", "session_id": "test"}),
            ("/api/ai_chat.php", {"session_id": "test", "export": "true"}),
        ]

        export_tested = False
        has_markings = False

        for endpoint, params in export_endpoints:
            status_code, body, headers = await client.get(endpoint, params=params)

            if status_code == 200 and len(body) > 50:
                export_tested = True
                # Check for CUI markings
                cui_indicators = [
                    "cui", "controlled unclassified",
                    "distribution", "handling",
                    "classification", "marking",
                    "fouo", "sensitive",
                ]
                body_lower = body.lower()
                if any(indicator in body_lower for indicator in cui_indicators):
                    has_markings = True
                break

        if not export_tested:
            # Also try POST-based export
            for endpoint, json_body in [
                ("/api/ai_chat.php", {"action": "export", "format": "csv"}),
            ]:
                status_code, body, headers = await client.post(
                    endpoint, json_body=json_body
                )
                if status_code == 200 and len(body) > 50:
                    export_tested = True
                    body_lower = body.lower()
                    if any(ind in body_lower for ind in ["cui", "controlled", "marking"]):
                        has_markings = True
                    break

        if export_tested and has_markings:
            export_status = Status.DEFENDED
            detail = "Data exports include CUI marking indicators."
        elif export_tested and not has_markings:
            export_status = Status.VULNERABLE
            detail = (
                "Data exports do not include CUI markings. "
                "NIST 3.1.3 requires that CUI be properly marked when exported "
                "to ensure authorized handling."
            )
        elif not export_tested:
            export_status = Status.VULNERABLE
            detail = (
                "No data export functionality detected. "
                "If CUI can be extracted via API responses, those responses "
                "should include CUI markings and handling instructions."
            )
        else:
            export_status = Status.PARTIAL
            detail = "Export functionality exists but CUI marking status unclear."

        results.append(self._make_result(
            variant="export_no_marking",
            status=export_status,
            severity=Severity.MEDIUM,
            evidence=(
                f"Export tested: {export_tested}, "
                f"CUI markings found: {has_markings}"
            ),
            details=detail,
            request={"export_endpoints_tested": len(export_endpoints)},
            response={"export_found": export_tested, "has_markings": has_markings},
        ))

        return results
