"""CUI retention beyond necessity — NIST SP 800-172 Control 3.14.5e.

Verifies that Controlled Unclassified Information (CUI) is not retained
beyond necessity in logs, error messages, temp files, caches, and API
responses.
"""

import json
import re
import time

from redteam.base import Attack, AttackResult, Severity, Status


class CUIRetentionAttack(Attack):
    name = "compliance.cui_retention"
    category = "compliance"
    severity = Severity.MEDIUM
    description = (
        "NIST 800-172 3.14.5e — Verify CUI is not retained beyond necessity "
        "in logs, caches, and responses"
    )

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. error_response_leakage
        #    Trigger errors and check if responses expose internal CUI
        # ----------------------------------------------------------------
        leakage_hits = []

        # a) Malformed JSON body to /api/ai_chat.php
        sc, body, headers = await client.post(
            "/api/ai_chat.php",
            raw_body="{{{not valid json at all",
        )
        internal_indicators = [
            "/var/www", "/opt/", "/home/", "/etc/",
            "stack trace", "traceback", "exception",
            "pg_connect", "mysqli_", "pdo", "odbc",
            "database error", "sql syntax", "relation ",
            "column ", "table ", "pg_query", "ora-",
            "sqlstate", "fatal error",
        ]
        body_lower = body.lower()
        for indicator in internal_indicators:
            if indicator in body_lower:
                leakage_hits.append(
                    f"Malformed JSON POST → HTTP {sc}: response contains '{indicator}'. "
                    f"Preview: {body[:300]}"
                )
                break

        # b) GET non-existent endpoint
        sc2, body2, _ = await client.get("/api/does_not_exist_redteam.php")
        body2_lower = body2.lower()
        for indicator in internal_indicators:
            if indicator in body2_lower:
                leakage_hits.append(
                    f"Non-existent endpoint GET → HTTP {sc2}: response contains '{indicator}'. "
                    f"Preview: {body2[:300]}"
                )
                break

        # c) Invalid action parameter
        sc3, body3, _ = await client.post(
            "/api/ai_chat.php",
            json_body={"action": "__redteam_invalid__", "data": None},
        )
        body3_lower = body3.lower()
        for indicator in internal_indicators:
            if indicator in body3_lower:
                leakage_hits.append(
                    f"Invalid action POST → HTTP {sc3}: response contains '{indicator}'. "
                    f"Preview: {body3[:300]}"
                )
                break

        if leakage_hits:
            err_status = Status.VULNERABLE
            err_detail = (
                f"{len(leakage_hits)} error response(s) leak internal system information "
                "(file paths, DB details, or stack traces). NIST 800-172 3.14.5e requires "
                "CUI not be retained or exposed in error output."
            )
        else:
            err_status = Status.DEFENDED
            err_detail = (
                "Error responses do not expose internal paths, database details, "
                "or stack traces. Error handling properly sanitizes output."
            )

        results.append(self._make_result(
            variant="error_response_leakage",
            status=err_status,
            evidence="\n".join(leakage_hits) if leakage_hits else "No internal info leaked",
            details=err_detail,
            request={"endpoints_probed": ["/api/ai_chat.php (POST malformed)", "/api/does_not_exist_redteam.php (GET)", "/api/ai_chat.php (POST invalid action)"]},
            response={"leaks_found": len(leakage_hits), "details": leakage_hits},
        ))

        # ----------------------------------------------------------------
        # 2. cache_headers_missing
        #    CUI endpoints must return Cache-Control: no-store
        # ----------------------------------------------------------------
        cui_endpoints = [
            "/api/ai_chat.php",
            "/api/admin/settings.php",
            "/api/admin/users.php",
        ]
        cache_issues = []
        cache_ok_count = 0

        for endpoint in cui_endpoints:
            sc, body, headers = await client.get(endpoint)
            cache_control = ""
            pragma = ""
            for key, val in headers.items():
                if key.lower() == "cache-control":
                    cache_control = val.lower()
                elif key.lower() == "pragma":
                    pragma = val.lower()

            has_no_store = "no-store" in cache_control
            has_pragma_no_cache = "no-cache" in pragma

            if not has_no_store:
                cache_issues.append(
                    f"{endpoint}: Cache-Control='{cache_control}', Pragma='{pragma}' — "
                    "missing 'no-store'. CUI may persist in browser or proxy caches."
                )
            else:
                cache_ok_count += 1

        if not cache_issues:
            cache_status = Status.DEFENDED
            cache_detail = (
                "All checked CUI endpoints include Cache-Control: no-store. "
                "Responses will not be cached by browsers or intermediaries."
            )
        elif cache_ok_count == 0:
            cache_status = Status.VULNERABLE
            cache_detail = (
                "No CUI endpoints include Cache-Control: no-store. "
                "CUI data may persist in browser, CDN, or proxy caches beyond session end. "
                "NIST 800-172 3.14.5e requires CUI not be retained beyond necessity."
            )
        else:
            cache_status = Status.VULNERABLE
            cache_detail = (
                f"{len(cache_issues)} of {len(cui_endpoints)} CUI endpoint(s) missing "
                "Cache-Control: no-store. Partial coverage leaves CUI retention risk."
            )

        results.append(self._make_result(
            variant="cache_headers_missing",
            status=cache_status,
            evidence="\n".join(cache_issues) if cache_issues else "All endpoints have no-store",
            details=cache_detail,
            request={"endpoints_checked": cui_endpoints},
            response={"issues": cache_issues, "compliant_count": cache_ok_count},
        ))

        # ----------------------------------------------------------------
        # 3. verbose_headers
        #    Responses should not reveal server/framework version info
        # ----------------------------------------------------------------
        sc, body, headers = await client.get("/api/ai_chat.php")

        verbose_hits = []
        for key, val in headers.items():
            key_lower = key.lower()
            val_lower = val.lower()
            if key_lower == "x-powered-by":
                verbose_hits.append(f"X-Powered-By: {val} — reveals runtime/framework")
            elif key_lower == "server" and re.search(r"[\d.]", val):
                # Server header with version number
                verbose_hits.append(f"Server: {val} — reveals server version")
            elif key_lower.startswith("x-debug"):
                verbose_hits.append(f"{key}: {val} — debug header present in production")
            elif key_lower in ("x-aspnet-version", "x-aspnetmvc-version"):
                verbose_hits.append(f"{key}: {val} — reveals .NET version")

        if verbose_hits:
            verbose_status = Status.PARTIAL
            verbose_detail = (
                f"{len(verbose_hits)} verbose header(s) detected. These aid reconnaissance "
                "and may reveal CUI processing infrastructure details. NIST 800-172 3.14.5e "
                "requires minimizing retention and exposure of system metadata."
            )
        else:
            verbose_status = Status.DEFENDED
            verbose_detail = (
                "No verbose server headers detected (X-Powered-By, versioned Server, "
                "X-Debug-*, X-AspNet-Version). Infrastructure details are not exposed."
            )

        results.append(self._make_result(
            variant="verbose_headers",
            status=verbose_status,
            evidence="\n".join(verbose_hits) if verbose_hits else "No verbose headers found",
            details=verbose_detail,
            request={"endpoint": "/api/ai_chat.php", "method": "GET"},
            response={"verbose_headers": verbose_hits},
        ))

        # ----------------------------------------------------------------
        # 4. session_data_after_logout
        #    After logout, CUI accessed pre-logout must not remain accessible
        # ----------------------------------------------------------------
        login_ok = await client.login(
            "redteam-sysadmin@test.com", "RedTeam$ysAdmin2026!"
        )

        if not login_ok:
            results.append(self._make_result(
                variant="session_data_after_logout",
                status=Status.ERROR,
                evidence="Login failed — cannot test session retention after logout.",
                details="Could not authenticate to perform pre/post-logout CUI comparison.",
            ))
        else:
            # Access CUI endpoint, capture snapshot of data
            sc_pre, body_pre, _ = await client.get("/api/ai_chat.php")
            pre_data_snippet = body_pre[:200] if body_pre else ""

            # Logout
            await client.post("/admin/logout.php", json_body={})
            # Small delay to allow session invalidation
            time.sleep(0.5)

            # Attempt same endpoint post-logout
            sc_post, body_post, _ = await client.get("/api/ai_chat.php")

            # Check if post-logout response contains same data fragment as pre-logout
            session_leaked = False
            if sc_post == 200 and pre_data_snippet and len(pre_data_snippet) > 20:
                # If a meaningful chunk of the pre-logout body reappears, session data leaked
                if pre_data_snippet[:50] in body_post:
                    session_leaked = True

            if session_leaked:
                sess_status = Status.VULNERABLE
                sess_evidence = (
                    f"Pre-logout CUI data fragment reappeared in post-logout response. "
                    f"HTTP {sc_post} after logout. Pre-logout preview: {pre_data_snippet[:100]}"
                )
                sess_detail = (
                    "CUI endpoint returns data after logout without re-authentication. "
                    "Session data or cached CUI is retained beyond session end. "
                    "NIST 800-172 3.14.5e requires CUI not persist beyond necessity."
                )
            elif sc_post in (401, 403):
                sess_status = Status.DEFENDED
                sess_evidence = f"Post-logout request returned HTTP {sc_post} — access denied."
                sess_detail = (
                    f"CUI endpoint correctly returns HTTP {sc_post} after logout. "
                    "Session data is invalidated on logout."
                )
            else:
                sess_status = Status.PARTIAL
                sess_evidence = (
                    f"Post-logout HTTP {sc_post}. Could not confirm CUI data reuse, "
                    "but endpoint may still be accessible."
                )
                sess_detail = (
                    f"Endpoint returned HTTP {sc_post} after logout (expected 401/403). "
                    "Session invalidation behavior is unclear."
                )

            results.append(self._make_result(
                variant="session_data_after_logout",
                status=sess_status,
                evidence=sess_evidence,
                details=sess_detail,
                request={"endpoint": "/api/ai_chat.php", "sequence": "login → GET → logout → GET"},
                response={"pre_logout_status": sc_pre, "post_logout_status": sc_post, "data_reappeared": session_leaked},
            ))

        # ----------------------------------------------------------------
        # 5. api_response_over_sharing
        #    API endpoints should return minimal fields — no password hashes,
        #    internal IDs, tokens, or audit metadata
        # ----------------------------------------------------------------
        sc, body, headers = await client.get("/api/admin/users.php")

        sensitive_fields = [
            "password", "passwd", "hash", "secret",
            "token", "api_key", "internal_id", "audit",
            "salt", "credential", "private_key",
        ]
        over_share_hits = []

        try:
            data = json.loads(body)
            body_str = json.dumps(data).lower()
        except (json.JSONDecodeError, TypeError):
            body_str = body.lower() if body else ""

        for field in sensitive_fields:
            # Use word-boundary-aware check: field as key in JSON
            pattern = rf'"{field}"'
            if re.search(pattern, body_str, re.IGNORECASE):
                over_share_hits.append(
                    f"Response contains field '{field}' — sensitive data should not be returned"
                )

        if over_share_hits:
            share_status = Status.VULNERABLE
            share_detail = (
                f"API response includes {len(over_share_hits)} sensitive field(s) that should "
                "not be returned. Over-sharing violates data minimization requirements. "
                "NIST 800-172 3.14.5e requires CUI not be retained or exposed beyond necessity."
            )
        elif sc in (401, 403):
            share_status = Status.DEFENDED
            share_detail = (
                f"Endpoint returned HTTP {sc} — protected by authentication. "
                "Could not confirm field exposure without valid credentials."
            )
        else:
            share_status = Status.DEFENDED
            share_detail = (
                "No sensitive fields (password, hash, token, secret, etc.) detected "
                "in API response. Data minimization appears enforced."
            )

        results.append(self._make_result(
            variant="api_response_over_sharing",
            status=share_status,
            evidence="\n".join(over_share_hits) if over_share_hits else f"No sensitive fields found (HTTP {sc})",
            details=share_detail,
            request={"endpoint": "/api/admin/users.php", "method": "GET"},
            response={"sensitive_fields_found": over_share_hits, "http_status": sc},
        ))

        # ----------------------------------------------------------------
        # 6. autocomplete_not_disabled
        #    Login/sensitive forms must have autocomplete="off" on sensitive fields
        # ----------------------------------------------------------------
        sc, body, headers = await client.get("/admin/login.php")

        autocomplete_issues = []

        if sc == 200 and body:
            # Find all input tags and check for autocomplete attribute
            input_tags = re.findall(r"<input[^>]+>", body, re.IGNORECASE)
            sensitive_input_types = {"password", "email", "text", "tel", "number"}

            for tag in input_tags:
                # Determine input type
                type_match = re.search(r'type=["\']?(\w+)["\']?', tag, re.IGNORECASE)
                input_type = type_match.group(1).lower() if type_match else "text"

                # Get name/id for context
                name_match = re.search(r'(?:name|id)=["\']?([^"\'>\s]+)["\']?', tag, re.IGNORECASE)
                input_name = name_match.group(1) if name_match else "(unnamed)"

                # Only check sensitive input types
                if input_type not in sensitive_input_types:
                    continue

                # Check autocomplete attribute
                autocomplete_match = re.search(r'autocomplete=["\']?([^"\'>\s]+)["\']?', tag, re.IGNORECASE)
                if not autocomplete_match:
                    autocomplete_issues.append(
                        f"<input type='{input_type}' name/id='{input_name}'> — "
                        "autocomplete attribute missing. Browser may cache this value."
                    )
                elif autocomplete_match.group(1).lower() not in ("off", "new-password"):
                    val = autocomplete_match.group(1)
                    if input_type == "password":
                        autocomplete_issues.append(
                            f"<input type='password' name/id='{input_name}'> — "
                            f"autocomplete='{val}' (should be 'off' or 'new-password')."
                        )

        if sc != 200:
            auto_status = Status.SKIPPED
            auto_evidence = f"Login page returned HTTP {sc} — could not inspect form fields."
            auto_detail = "Could not retrieve login page to check autocomplete attributes."
        elif autocomplete_issues:
            auto_status = Status.VULNERABLE
            auto_evidence = "\n".join(autocomplete_issues)
            auto_detail = (
                f"{len(autocomplete_issues)} sensitive input field(s) missing autocomplete='off'. "
                "Browsers may store CUI entered into these fields beyond session end. "
                "NIST 800-172 3.14.5e requires CUI not be retained unnecessarily."
            )
        else:
            auto_status = Status.DEFENDED
            auto_evidence = f"All sensitive input fields have autocomplete disabled. ({len(input_tags)} inputs inspected)"
            auto_detail = (
                "Login form sensitive fields correctly set autocomplete='off' or 'new-password'. "
                "Browsers will not cache CUI entered in these fields."
            )

        results.append(self._make_result(
            variant="autocomplete_not_disabled",
            status=auto_status,
            evidence=auto_evidence,
            details=auto_detail,
            request={"endpoint": "/admin/login.php", "method": "GET"},
            response={"http_status": sc, "issues": autocomplete_issues},
        ))

        return results
