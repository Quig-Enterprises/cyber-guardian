"""Anomaly detection evasion — NIST SP 800-172 Control 3.14.2e.

Verifies that the system detects anomalous or suspicious behavior patterns
that an Advanced Persistent Threat (APT) would generate. Tests rapid
sequential access, impossible travel, off-hours access patterns, bulk data
enumeration, failed authentication flooding, and unusual user agent strings.
"""

import asyncio
import json
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class AnomalyDetectionEvasionAttack(Attack):
    name = "compliance.anomaly_detection_evasion"
    category = "compliance"
    severity = Severity.HIGH
    description = (
        "NIST 800-172 3.14.2e — Verify monitoring detects anomalous/suspicious behavior"
    )

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. rapid_sequential_access
        # ----------------------------------------------------------------
        rapid_tasks = [client.get("/api/ai_chat.php") for _ in range(20)]
        t_start = time.monotonic()
        rapid_responses = await asyncio.gather(*rapid_tasks, return_exceptions=True)
        elapsed = time.monotonic() - t_start

        successful = [
            r for r in rapid_responses
            if not isinstance(r, Exception) and r[0] == 200
        ]
        error_responses = [r for r in rapid_responses if isinstance(r, Exception)]
        blocked = [
            r for r in rapid_responses
            if not isinstance(r, Exception) and r[0] in (429, 503, 403)
        ]

        if len(successful) == 20:
            rapid_status = Status.VULNERABLE
            rapid_evidence = (
                f"All 20 rapid GET requests to /api/ai_chat.php returned HTTP 200. "
                f"Completed in {elapsed:.2f}s. No rate-limiting or blocking observed."
            )
            rapid_detail = (
                "The system did not detect or throttle 20 concurrent requests issued "
                "within a 2-second window. An APT conducting reconnaissance or data "
                "exfiltration via rapid enumeration would go undetected. "
                "NIST SP 800-172 3.14.2e requires systems to identify anomalous "
                "patterns such as unusually high request rates from a single source."
            )
        elif blocked:
            rapid_status = Status.DEFENDED
            rapid_evidence = (
                f"{len(blocked)} of 20 requests were blocked or rate-limited "
                f"(HTTP 429/503/403). {len(successful)} succeeded. "
                f"Elapsed: {elapsed:.2f}s."
            )
            rapid_detail = (
                "The system detected and throttled rapid sequential access. "
                "Rate-limiting controls are functioning as required by NIST SP 800-172 "
                "3.14.2e anomaly detection requirements."
            )
        elif error_responses:
            rapid_status = Status.PARTIAL
            rapid_evidence = (
                f"{len(successful)} requests returned 200, {len(error_responses)} "
                f"resulted in errors, {len(blocked)} were blocked. Elapsed: {elapsed:.2f}s."
            )
            rapid_detail = (
                "Inconsistent responses to rapid sequential access — some requests "
                "errored but none were cleanly rate-limited with HTTP 429. "
                "Anomaly detection behavior is unclear and warrants manual review."
            )
        else:
            rapid_status = Status.PARTIAL
            rapid_evidence = (
                f"{len(successful)} of 20 requests succeeded (non-200, non-blocked). "
                f"Elapsed: {elapsed:.2f}s."
            )
            rapid_detail = (
                "Not all requests returned 200 but no explicit rate-limiting was "
                "detected. The system behavior under rapid sequential load is ambiguous."
            )

        results.append(self._make_result(
            variant="rapid_sequential_access",
            status=rapid_status,
            evidence=rapid_evidence,
            details=rapid_detail,
            request={
                "path": "/api/ai_chat.php",
                "method": "GET",
                "count": 20,
                "mode": "asyncio.gather (concurrent)",
            },
            response={
                "successful_200": len(successful),
                "blocked_429_503_403": len(blocked),
                "errors": len(error_responses),
                "elapsed_seconds": round(elapsed, 3),
            },
        ))

        # ----------------------------------------------------------------
        # 2. impossible_travel
        # ----------------------------------------------------------------
        ip_us = "203.0.113.1"
        ip_other = "198.51.100.1"

        sc_us, body_us, headers_us = await client.get(
            "/api/ai_chat.php",
            headers={"X-Forwarded-For": ip_us},
        )
        sc_other, body_other, headers_other = await client.get(
            "/api/ai_chat.php",
            headers={"X-Forwarded-For": ip_other},
        )

        if sc_us == 200 and sc_other == 200:
            travel_status = Status.VULNERABLE
            travel_evidence = (
                f"Request from X-Forwarded-For: {ip_us} returned HTTP {sc_us}. "
                f"Immediate follow-up request from X-Forwarded-For: {ip_other} "
                f"returned HTTP {sc_other}. Both succeeded without any alert or block."
            )
            travel_detail = (
                "The system allows requests from geographically distinct IP addresses "
                "in immediate succession without triggering an impossible travel alert. "
                "A compromised credential used from two different geolocations "
                "simultaneously would go undetected. NIST SP 800-172 3.14.2e requires "
                "identification of anomalous or suspicious patterns — impossible travel "
                "is a canonical APT indicator of credential theft."
            )
        elif sc_us in (403, 401) or sc_other in (403, 401):
            travel_status = Status.DEFENDED
            travel_evidence = (
                f"X-Forwarded-For: {ip_us} → HTTP {sc_us}. "
                f"X-Forwarded-For: {ip_other} → HTTP {sc_other}. "
                "At least one request was blocked, suggesting IP-based controls."
            )
            travel_detail = (
                "The system blocked at least one of the geographically distinct "
                "requests. IP-based access controls or geo-blocking may be in place."
            )
        else:
            travel_status = Status.PARTIAL
            travel_evidence = (
                f"X-Forwarded-For: {ip_us} → HTTP {sc_us}. "
                f"X-Forwarded-For: {ip_other} → HTTP {sc_other}. "
                "Responses were not clearly blocked but also not both 200."
            )
            travel_detail = (
                "Inconclusive impossible travel test — requests did not both return "
                "200, but no explicit block was observed. Manual review recommended."
            )

        results.append(self._make_result(
            variant="impossible_travel",
            status=travel_status,
            evidence=travel_evidence,
            details=travel_detail,
            request={
                "path": "/api/ai_chat.php",
                "method": "GET",
                "request_1_header": f"X-Forwarded-For: {ip_us}",
                "request_2_header": f"X-Forwarded-For: {ip_other}",
                "note": "Requests issued in immediate succession",
            },
            response={
                "status_us": sc_us,
                "status_other": sc_other,
            },
        ))

        # ----------------------------------------------------------------
        # 3. off_hours_access
        # ----------------------------------------------------------------
        unusual_ip = "185.220.101.1"  # Tor exit node range
        admin_paths = [
            "/api/admin/users.php",
            "/api/admin/settings.php",
            "/api/admin/services.php",
        ]

        off_hours_results = []
        for path in admin_paths:
            sc, body, hdrs = await client.get(
                path,
                headers={"X-Forwarded-For": unusual_ip},
            )
            off_hours_results.append({"path": path, "status": sc, "body_preview": body[:100]})

        normal_responses = [r for r in off_hours_results if r["status"] == 200]
        blocked_off = [r for r in off_hours_results if r["status"] in (403, 401, 429)]

        if normal_responses:
            off_status = Status.PARTIAL
            off_evidence = (
                f"{len(normal_responses)} of {len(admin_paths)} admin endpoint(s) "
                f"responded normally (HTTP 200) to requests from unusual source IP "
                f"{unusual_ip} with no apparent alerting or restriction. "
                + "; ".join(f"{r['path']} → {r['status']}" for r in off_hours_results)
            )
            off_detail = (
                "Admin endpoints respond normally regardless of source IP. "
                "Requests from unusual IP ranges (e.g., Tor exits, anonymizers) "
                "to sensitive endpoints are not restricted or flagged. "
                "NIST SP 800-172 3.14.2e requires anomaly detection to identify "
                "access from unusual sources or at unusual times. Without source IP "
                "analysis, off-hours APT access from anonymized infrastructure "
                "would be invisible to defenders."
            )
        else:
            off_status = Status.DEFENDED
            off_evidence = (
                f"All admin endpoints returned non-200 for requests from "
                f"X-Forwarded-For: {unusual_ip}. "
                + "; ".join(f"{r['path']} → {r['status']}" for r in off_hours_results)
            )
            off_detail = (
                "Admin endpoints are not accessible from the tested unusual source IP. "
                "Access controls appear to restrict admin functionality regardless "
                "of X-Forwarded-For manipulation."
            )

        results.append(self._make_result(
            variant="off_hours_access",
            status=off_status,
            evidence=off_evidence,
            details=off_detail,
            request={
                "paths_tested": admin_paths,
                "header": f"X-Forwarded-For: {unusual_ip}",
                "method": "GET",
            },
            response={"endpoint_results": off_hours_results},
        ))

        # ----------------------------------------------------------------
        # 4. bulk_data_enumeration
        # ----------------------------------------------------------------
        enum_tasks = [
            client.get("/api/vessels.php", params={"id": str(i)})
            for i in range(1, 51)
        ]
        enum_responses = await asyncio.gather(*enum_tasks, return_exceptions=True)

        enum_200 = [
            i + 1
            for i, r in enumerate(enum_responses)
            if not isinstance(r, Exception) and r[0] == 200
        ]
        enum_blocked = [
            i + 1
            for i, r in enumerate(enum_responses)
            if not isinstance(r, Exception) and r[0] in (429, 503, 403)
        ]
        enum_errors = sum(1 for r in enum_responses if isinstance(r, Exception))

        if len(enum_200) >= 10 and not enum_blocked:
            enum_status = Status.VULNERABLE
            enum_evidence = (
                f"{len(enum_200)} of 50 enumerated resource IDs (/api/vessels.php?id=1..50) "
                f"returned HTTP 200 without any throttling or blocking. "
                f"IDs that succeeded: {enum_200[:10]}{'...' if len(enum_200) > 10 else ''}. "
                "No rate-limiting responses (HTTP 429/503/403) observed."
            )
            enum_detail = (
                "The system does not detect or throttle bulk sequential enumeration of "
                "resource IDs. An APT performing data harvesting could enumerate all "
                "vessel records without triggering any anomaly detection controls. "
                "NIST SP 800-172 3.14.2e requires detection of suspicious patterns "
                "including bulk data access and enumeration behavior."
            )
        elif enum_blocked:
            enum_status = Status.DEFENDED
            enum_evidence = (
                f"{len(enum_blocked)} of 50 requests were blocked/throttled "
                f"(HTTP 429/503/403). {len(enum_200)} returned 200. "
                "Rate-limiting triggered during bulk enumeration."
            )
            enum_detail = (
                "The system detected and throttled bulk sequential ID enumeration. "
                "Anomaly detection or rate-limiting controls are active for this "
                "endpoint, consistent with NIST SP 800-172 3.14.2e requirements."
            )
        elif len(enum_200) < 5:
            enum_status = Status.DEFENDED
            enum_evidence = (
                f"Only {len(enum_200)} of 50 enumerated IDs returned HTTP 200. "
                "The majority were rejected, suggesting IDs do not exist or access "
                "is restricted."
            )
            enum_detail = (
                "Bulk enumeration yielded few valid responses, likely because the "
                "resource IDs do not exist or are restricted. Enumeration risk is low."
            )
        else:
            enum_status = Status.PARTIAL
            enum_evidence = (
                f"{len(enum_200)} of 50 IDs returned 200, {len(enum_blocked)} blocked, "
                f"{enum_errors} errors. Partial enumeration success without clear throttling."
            )
            enum_detail = (
                "Partial enumeration succeeded without consistent throttling. "
                "Anomaly detection behavior is inconsistent and warrants review."
            )

        results.append(self._make_result(
            variant="bulk_data_enumeration",
            status=enum_status,
            evidence=enum_evidence,
            details=enum_detail,
            request={
                "path": "/api/vessels.php",
                "method": "GET",
                "param": "id",
                "range": "1-50",
                "mode": "asyncio.gather (concurrent)",
            },
            response={
                "ids_returned_200": enum_200,
                "ids_blocked": enum_blocked,
                "errors": enum_errors,
            },
        ))

        # ----------------------------------------------------------------
        # 5. failed_auth_flood
        # ----------------------------------------------------------------
        bogus_password = f"INVALID-{uuid.uuid4().hex}"
        auth_statuses = []
        last_body = ""
        last_headers = {}

        for attempt in range(1, 11):
            sc, body, hdrs = await client.post(
                "/api/auth/login.php",
                json_body={
                    "email": "testuser@example.com",
                    "password": bogus_password,
                },
            )
            auth_statuses.append({"attempt": attempt, "status": sc})
            last_body = body
            last_headers = hdrs

        final_attempt = auth_statuses[-1]
        locked_statuses = {401, 403, 423, 429}

        early_lockout = next(
            (a for a in auth_statuses if a["status"] in locked_statuses),
            None,
        )

        if final_attempt["status"] not in locked_statuses and not early_lockout:
            brute_status = Status.VULNERABLE
            brute_evidence = (
                f"All 10 rapid failed login attempts to /api/auth/login.php "
                f"completed without account lockout or throttling. "
                f"Final attempt (attempt 10) returned HTTP {final_attempt['status']}. "
                f"Response preview: {last_body[:150]}"
            )
            brute_detail = (
                "The system does not detect or respond to a flood of failed "
                "authentication attempts. An APT conducting credential stuffing or "
                "password spraying would face no resistance. NIST SP 800-172 3.14.2e "
                "requires anomaly detection to identify repeated authentication "
                "failures as a suspicious pattern indicative of brute force attacks."
            )
        elif early_lockout:
            lockout_attempt = early_lockout["attempt"]
            brute_status = Status.DEFENDED
            brute_evidence = (
                f"Account/IP was locked or throttled at attempt {lockout_attempt} "
                f"(HTTP {early_lockout['status']}). "
                f"Attempt history: {json.dumps(auth_statuses)}"
            )
            brute_detail = (
                f"Failed authentication flood was detected and blocked after "
                f"{lockout_attempt} attempt(s). Brute force detection is active and "
                "aligned with NIST SP 800-172 3.14.2e anomaly detection requirements."
            )
        else:
            brute_status = Status.PARTIAL
            brute_evidence = (
                f"Final attempt returned HTTP {final_attempt['status']} but no "
                "clear lockout or throttling was observed. "
                f"Attempt history: {json.dumps(auth_statuses)}"
            )
            brute_detail = (
                "The final failed authentication attempt returned a non-200 status "
                "but the response pattern does not clearly indicate rate-limiting "
                "or lockout. Manual verification of account lockout policy recommended."
            )

        results.append(self._make_result(
            variant="failed_auth_flood",
            status=brute_status,
            evidence=brute_evidence,
            details=brute_detail,
            request={
                "path": "/api/auth/login.php",
                "method": "POST",
                "attempts": 10,
                "email": "testuser@example.com",
                "password": "(intentionally invalid)",
            },
            response={
                "attempt_statuses": auth_statuses,
                "final_status": final_attempt["status"],
                "final_body_preview": last_body[:200],
            },
        ))

        # ----------------------------------------------------------------
        # 6. unusual_user_agent
        # ----------------------------------------------------------------
        suspicious_agents = [
            "sqlmap/1.0",
            "nikto",
            "python-requests/2.0 (automated)",
            "",
        ]

        ua_results = []
        for ua in suspicious_agents:
            headers = {"User-Agent": ua} if ua else {"User-Agent": ""}
            sc, body, hdrs = await client.get("/api/ai_chat.php", headers=headers)
            ua_results.append({
                "user_agent": ua if ua else "(empty string)",
                "status": sc,
                "body_preview": body[:100],
            })

        ua_200 = [r for r in ua_results if r["status"] == 200]
        ua_blocked = [r for r in ua_results if r["status"] in (403, 429, 503)]

        if len(ua_200) == len(suspicious_agents):
            ua_status = Status.PARTIAL
            ua_evidence = (
                "All 4 suspicious user agent strings returned HTTP 200 from "
                "/api/ai_chat.php with no blocking or challenge response. "
                "Tested agents: sqlmap/1.0, nikto, python-requests/2.0 (automated), "
                "and empty string. "
                + "; ".join(
                    f"'{r['user_agent']}' → HTTP {r['status']}" for r in ua_results
                )
            )
            ua_detail = (
                "The system does not perform user agent-based anomaly detection. "
                "Well-known attack tool signatures (sqlmap, nikto) and automated "
                "scanner indicators pass through without restriction or alerting. "
                "While UA-based detection alone is not sufficient, its complete "
                "absence means one layer of anomaly signal is missing. "
                "NIST SP 800-172 3.14.2e expects systems to identify anomalous "
                "patterns — known attack tool UAs are a common and easily detectable "
                "APT indicator."
            )
        elif ua_blocked:
            ua_status = Status.DEFENDED
            ua_evidence = (
                f"{len(ua_blocked)} of {len(suspicious_agents)} suspicious user agents "
                "were blocked (HTTP 403/429/503). "
                + "; ".join(
                    f"'{r['user_agent']}' → HTTP {r['status']}" for r in ua_results
                )
            )
            ua_detail = (
                "The system detects and blocks requests carrying suspicious or known "
                "attack tool user agent strings. User agent anomaly detection is active."
            )
        else:
            ua_status = Status.PARTIAL
            ua_evidence = (
                f"{len(ua_200)} of {len(suspicious_agents)} suspicious UAs returned "
                f"200, {len(ua_blocked)} were blocked. "
                + "; ".join(
                    f"'{r['user_agent']}' → HTTP {r['status']}" for r in ua_results
                )
            )
            ua_detail = (
                "Inconsistent user agent anomaly detection — some suspicious agents "
                "are blocked while others pass through. Coverage is partial."
            )

        results.append(self._make_result(
            variant="unusual_user_agent",
            status=ua_status,
            evidence=ua_evidence,
            details=ua_detail,
            request={
                "path": "/api/ai_chat.php",
                "method": "GET",
                "user_agents_tested": [ua if ua else "(empty)" for ua in suspicious_agents],
            },
            response={"ua_results": ua_results},
        ))

        return results
