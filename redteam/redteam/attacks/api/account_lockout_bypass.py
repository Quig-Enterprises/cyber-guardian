"""Account lockout bypass — NIST SP 800-171 Control 3.1.8.

Tests whether brute-force login protection can be bypassed via IP
rotation, whether rate limiting is applied to authentication attempts,
and whether rate limit headers are present.
"""

import asyncio
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class AccountLockoutBypassAttack(Attack):
    name = "api.account_lockout_bypass"
    category = "api"
    severity = Severity.MEDIUM
    description = (
        "NIST 3.1.8 — Verify account lockout after failed login attempts "
        "and resistance to IP rotation bypass"
    )

    LOGIN_PATH = "/api/auth/login.php"
    TARGET_EMAIL = "redteam-sysadmin@test.com"
    WRONG_PASSWORD = "WrongPassword!999"

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. IP rotation bypass — same account, different X-Forwarded-For
        # ----------------------------------------------------------------
        spoofed_ips = [
            "10.0.0.1", "10.0.0.2", "10.0.0.3",
            "10.0.0.4", "10.0.0.5", "10.0.0.6",
            "192.168.1.100", "172.16.0.50",
        ]

        ip_statuses = []
        for ip in spoofed_ips:
            status_code, body, headers = await client.post(
                self.LOGIN_PATH,
                json_body={
                    "email": self.TARGET_EMAIL,
                    "password": self.WRONG_PASSWORD,
                },
                headers={"X-Forwarded-For": ip},
                cookies={},
            )
            ip_statuses.append(status_code)

        # If all attempts returned 401 (wrong password) and none got 429/423,
        # the server is not tracking per-account failures across IPs.
        locked_out = any(s in (429, 423, 403) for s in ip_statuses)
        all_normal_failure = all(s == 401 for s in ip_statuses)

        if locked_out:
            ip_status = Status.DEFENDED
            lockout_at = next(
                i for i, s in enumerate(ip_statuses) if s in (429, 423, 403)
            )
            detail = (
                f"Account locked/rate-limited after {lockout_at + 1} attempts despite "
                "IP rotation. Server tracks failures per-account, not per-IP."
            )
        elif all_normal_failure:
            ip_status = Status.VULNERABLE
            detail = (
                f"All {len(spoofed_ips)} login attempts with different X-Forwarded-For "
                "IPs returned 401 (wrong password) without lockout. "
                "Account lockout can be bypassed via IP spoofing."
            )
        else:
            ip_status = Status.PARTIAL
            detail = (
                f"Mixed responses during IP rotation: {set(ip_statuses)}. "
                "Some protection may exist but lockout behavior is inconsistent."
            )

        results.append(self._make_result(
            variant="ip_rotation",
            status=ip_status,
            severity=Severity.MEDIUM,
            evidence=(
                f"Tested {len(spoofed_ips)} IPs. Statuses: {ip_statuses}. "
                f"Locked out: {locked_out}"
            ),
            details=detail,
            request={"ips_tested": len(spoofed_ips), "target": self.TARGET_EMAIL},
            response={"status_distribution": {str(s): ip_statuses.count(s) for s in set(ip_statuses)}},
        ))

        # ----------------------------------------------------------------
        # 2. Rapid login attempts — 10 fast failures from same source
        # ----------------------------------------------------------------
        num_attempts = 10
        start = time.monotonic()
        rapid_statuses = []

        for i in range(num_attempts):
            status_code, body, headers = await client.post(
                self.LOGIN_PATH,
                json_body={
                    "email": self.TARGET_EMAIL,
                    "password": f"{self.WRONG_PASSWORD}_{i}",
                },
                cookies={},
            )
            rapid_statuses.append(status_code)

        elapsed = time.monotonic() - start
        locked_out = any(s in (429, 423, 403) for s in rapid_statuses)

        if locked_out:
            lockout_at = next(
                i for i, s in enumerate(rapid_statuses) if s in (429, 423, 403)
            )
            rapid_status = Status.DEFENDED
            detail = (
                f"Rate limited after {lockout_at + 1} rapid attempts in {elapsed:.1f}s. "
                "Account lockout is enforced for brute-force protection."
            )
        else:
            rapid_status = Status.VULNERABLE
            detail = (
                f"All {num_attempts} rapid login failures completed in {elapsed:.1f}s "
                "without lockout or rate limiting. Brute-force attacks are possible."
            )

        results.append(self._make_result(
            variant="rapid_attempts",
            status=rapid_status,
            severity=Severity.MEDIUM,
            evidence=(
                f"Sent {num_attempts} attempts in {elapsed:.1f}s. "
                f"Statuses: {rapid_statuses}. Locked out: {locked_out}"
            ),
            details=detail,
            request={"attempts": num_attempts, "elapsed_sec": round(elapsed, 2)},
            response={
                "status_distribution": {
                    str(s): rapid_statuses.count(s) for s in set(rapid_statuses)
                }
            },
        ))

        # ----------------------------------------------------------------
        # 3. Rate limit headers check
        # ----------------------------------------------------------------
        # Send a single login attempt and inspect response headers
        status_code, body, headers = await client.post(
            self.LOGIN_PATH,
            json_body={
                "email": self.TARGET_EMAIL,
                "password": self.WRONG_PASSWORD,
            },
            cookies={},
        )

        rate_limit_headers = {}
        for header_name in [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
            "RateLimit-Limit",
            "RateLimit-Remaining",
            "RateLimit-Reset",
        ]:
            # Case-insensitive header search
            for key, val in headers.items():
                if key.lower() == header_name.lower():
                    rate_limit_headers[header_name] = val

        if rate_limit_headers:
            header_status = Status.DEFENDED
            detail = (
                f"Rate limit headers present: {list(rate_limit_headers.keys())}. "
                "Server communicates rate limiting policy to clients."
            )
        else:
            header_status = Status.VULNERABLE
            detail = (
                "No rate limit headers found in login response. "
                "Server does not communicate rate limiting policy. "
                "NIST 3.1.8 recommends informing clients of lockout policy."
            )

        results.append(self._make_result(
            variant="rate_limit_header_check",
            status=header_status,
            severity=Severity.LOW,
            evidence=(
                f"Response headers checked. Rate limit headers found: "
                f"{rate_limit_headers if rate_limit_headers else 'none'}"
            ),
            details=detail,
            request={"endpoint": self.LOGIN_PATH},
            response={"rate_limit_headers": rate_limit_headers},
        ))

        return results
