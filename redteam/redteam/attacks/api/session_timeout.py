"""Session timeout and management — NIST SP 800-171 Controls 3.1.10, 3.1.11.

Verifies that session tokens have appropriate expiration, that the
server tracks active sessions, and that concurrent session limits
are enforced.
"""

import json
import time

import jwt as pyjwt

from redteam.base import Attack, AttackResult, Severity, Status


class SessionTimeoutAttack(Attack):
    name = "api.session_timeout"
    category = "api"
    severity = Severity.HIGH
    description = (
        "NIST 3.1.10/3.1.11 — Verify session timeout, server-side "
        "session tracking, and concurrent session controls"
    )

    MAX_TOKEN_HOURS = 8  # NIST guideline: sessions should not exceed 8 hours

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # Authenticate to get a real JWT
        login_ok = await client.login(
            "redteam-sysadmin@test.com", "RedTeam$ysAdmin2026!"
        )
        if not login_ok:
            results.append(self._make_result(
                variant="long_token_validity",
                status=Status.ERROR,
                evidence="Login failed — cannot inspect JWT expiration.",
                details="Could not authenticate to test session timeout.",
            ))
            return results

        session_token = client._cookies.get("eqmon_session", "")

        # ----------------------------------------------------------------
        # 1. Check JWT exp claim — if >8 hours, VULNERABLE
        # ----------------------------------------------------------------
        exp_hours = None
        try:
            # Decode without verification to inspect claims
            claims = pyjwt.decode(session_token, options={"verify_signature": False})
            iat = claims.get("iat", 0)
            exp = claims.get("exp", 0)
            if iat and exp:
                exp_hours = (exp - iat) / 3600.0
        except Exception as e:
            results.append(self._make_result(
                variant="long_token_validity",
                status=Status.ERROR,
                evidence=f"Failed to decode JWT: {e}",
                details="Could not inspect JWT claims for expiration analysis.",
            ))
            exp_hours = None

        if exp_hours is not None:
            if exp_hours > self.MAX_TOKEN_HOURS:
                token_status = Status.VULNERABLE
                detail = (
                    f"JWT validity is {exp_hours:.1f} hours (iat→exp). "
                    f"NIST 3.1.10 recommends max {self.MAX_TOKEN_HOURS}h. "
                    "Long-lived tokens increase the window for stolen credential abuse."
                )
            else:
                token_status = Status.DEFENDED
                detail = (
                    f"JWT validity is {exp_hours:.1f} hours, within the "
                    f"{self.MAX_TOKEN_HOURS}h guideline."
                )

            results.append(self._make_result(
                variant="long_token_validity",
                status=token_status,
                severity=Severity.HIGH,
                evidence=(
                    f"Token lifetime: {exp_hours:.1f}h, "
                    f"iat: {claims.get('iat')}, exp: {claims.get('exp')}"
                ),
                details=detail,
                request={"token": "decoded from login response"},
                response={"exp_hours": round(exp_hours, 1)},
            ))

        # ----------------------------------------------------------------
        # 2. Server-side session tracking
        # ----------------------------------------------------------------
        # If the server only trusts the JWT without maintaining a session
        # store, there is no way to revoke tokens (logout is meaningless).
        # Test: call logout, then reuse the old token.
        old_cookies = dict(client._cookies)

        # Attempt logout
        logout_code, logout_body, _ = await client.post(
            "/api/auth/login.php",
            json_body={"action": "logout"},
            cookies=old_cookies,
        )

        # Now try to use the old token
        status_code, body, headers = await client.get(
            "/api/ai_chat.php",
            params={"session_id": "redteam-session-reuse-test"},
            cookies=old_cookies,
        )

        if status_code == 200:
            session_status = Status.VULNERABLE
            detail = (
                f"Old JWT still accepted after logout (status {status_code}). "
                "Server does not track active sessions — tokens cannot be revoked. "
                "NIST 3.1.11 requires session termination capability."
            )
        elif status_code == 401:
            session_status = Status.DEFENDED
            detail = (
                "Old JWT rejected after logout (401). "
                "Server maintains server-side session tracking and can revoke tokens."
            )
        else:
            session_status = Status.PARTIAL
            detail = (
                f"Post-logout request returned {status_code}. "
                "Session revocation behavior unclear."
            )

        results.append(self._make_result(
            variant="no_server_session_tracking",
            status=session_status,
            severity=Severity.HIGH,
            evidence=(
                f"Logout status: {logout_code}, "
                f"Post-logout request status: {status_code}, Body: {body[:200]}"
            ),
            details=detail,
            request={"action": "reuse token after logout"},
            response={"status": status_code},
        ))

        # ----------------------------------------------------------------
        # 3. Concurrent sessions allowed
        # ----------------------------------------------------------------
        # Login again (session 1)
        login_ok_1 = await client.login(
            "redteam-sysadmin@test.com", "RedTeam$ysAdmin2026!"
        )
        session_1_cookies = dict(client._cookies)

        # Login a second time (session 2) — simulating different location
        login_ok_2 = await client.login(
            "redteam-sysadmin@test.com", "RedTeam$ysAdmin2026!"
        )
        session_2_cookies = dict(client._cookies)

        # Check if both sessions still work
        status_1, body_1, _ = await client.get(
            "/api/ai_chat.php",
            params={"session_id": "redteam-concurrent-s1"},
            cookies=session_1_cookies,
        )
        status_2, body_2, _ = await client.get(
            "/api/ai_chat.php",
            params={"session_id": "redteam-concurrent-s2"},
            cookies=session_2_cookies,
        )

        both_work = status_1 == 200 and status_2 == 200
        if both_work:
            concurrent_status = Status.VULNERABLE
            detail = (
                "Both concurrent sessions accepted (200, 200). "
                "No concurrent session limiting is enforced. "
                "NIST 3.1.10 recommends limiting concurrent sessions."
            )
        elif status_1 == 401 or status_2 == 401:
            concurrent_status = Status.DEFENDED
            invalidated = "session 1" if status_1 == 401 else "session 2"
            detail = (
                f"New login invalidated {invalidated}. "
                "Server enforces single-session policy."
            )
        else:
            concurrent_status = Status.PARTIAL
            detail = (
                f"Session 1: {status_1}, Session 2: {status_2}. "
                "Concurrent session behavior unclear."
            )

        results.append(self._make_result(
            variant="concurrent_sessions_allowed",
            status=concurrent_status,
            severity=Severity.MEDIUM,
            evidence=(
                f"Session 1 status: {status_1}, Session 2 status: {status_2}, "
                f"Both active: {both_work}"
            ),
            details=detail,
            request={"sessions": 2, "same_user": True},
            response={"session_1": status_1, "session_2": status_2},
        ))

        return results
