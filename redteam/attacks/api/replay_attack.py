"""Replay attack tests for API session and request integrity.

NIST SP 800-172 3.5.1e: Employ replay-resistant authentication mechanisms
for network access to privileged and non-privileged accounts.

This module verifies that the API correctly invalidates session tokens after
logout, enforces strict JWT expiry without clock-skew tolerance, and provides
idempotency or nonce protection on state-mutating requests.
"""

import asyncio
import json
import time
import uuid

import jwt as pyjwt

from redteam.base import Attack, AttackResult, Severity, Status


class ReplayAttack(Attack):
    name = "api.replay_attack"
    category = "api"
    severity = Severity.HIGH
    description = (
        "Replay attack resistance per NIST SP 800-172 3.5.1e — "
        "tests session cookie replay after logout, duplicate-request idempotency, "
        "just-expired JWT acceptance, delayed request replay, and "
        "cross-session cookie reuse."
    )

    JWT_SECRET = "eqmon_jwt_secret_2026_artemis_integration"

    PROTECTED_PATH = "/api/ai_chat.php"
    LOGOUT_PATH = "/api/auth/logout.php"
    SETTINGS_PATH = "/api/admin/settings.php"

    def _expired_jwt(self) -> str:
        """Build a JWT that expired exactly 1 second ago."""
        now = int(time.time())
        payload = {
            "iat": now - 3600,
            "exp": now - 1,
            "user_id": "redteam-replay",
            "instance_id": "default",
            "email": "redteam-sysadmin@example.com",
            "role": "system-admin",
            "salt_version": 1,
            "auth_source": "eqmon",
        }
        return pyjwt.encode(payload, self.JWT_SECRET, algorithm="HS256")

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ------------------------------------------------------------------
        # Variant 1: cookie_replay_after_logout
        # Capture session cookie, logout, then replay the stale cookie.
        # A properly implemented server must invalidate server-side session
        # records on logout so that a captured cookie cannot be reused.
        # ------------------------------------------------------------------
        # Step 1a — make an authenticated request to capture cookie state.
        session_id = f"redteam-replay-{uuid.uuid4().hex[:8]}"
        status_before, body_before, headers_before = await client.get(
            self.PROTECTED_PATH,
            params={"session_id": session_id},
        )
        # Snapshot the cookies that were active for that request.
        captured_cookies: dict = dict(client._cookies)

        # Step 1b — logout using the current (valid) session.
        logout_status, logout_body, _ = await client.post(
            self.LOGOUT_PATH,
            json_body={},
        )

        # Step 1c — replay the OLD captured cookie against the protected endpoint.
        replay_status, replay_body, _ = await client.get(
            self.PROTECTED_PATH,
            params={"session_id": session_id},
            cookies=captured_cookies,
        )

        if replay_status == 200:
            v1_status = Status.VULNERABLE
            v1_evidence = (
                f"Pre-logout: {status_before}, logout: {logout_status}, "
                f"replay: {replay_status} — old cookie still accepted after logout."
            )
            v1_details = (
                "Session cookie remained valid after logout. An attacker who "
                "captures a session token (e.g. via network sniffing) can reuse "
                "it indefinitely. Server must invalidate session server-side on "
                "logout (NIST SP 800-172 3.5.1e)."
            )
        else:
            v1_status = Status.DEFENDED
            v1_evidence = (
                f"Pre-logout: {status_before}, logout: {logout_status}, "
                f"replay: {replay_status} — old cookie correctly rejected."
            )
            v1_details = (
                f"Server returned {replay_status} when replaying a cookie after "
                "logout. Session invalidation is working correctly."
            )

        results.append(self._make_result(
            variant="cookie_replay_after_logout",
            status=v1_status,
            evidence=v1_evidence,
            details=v1_details,
            request={
                "step1": f"GET {self.PROTECTED_PATH} (capture cookies)",
                "step2": f"POST {self.LOGOUT_PATH} (logout)",
                "step3": f"GET {self.PROTECTED_PATH} with captured cookies (replay)",
            },
            response={
                "pre_logout_status": status_before,
                "logout_status": logout_status,
                "replay_status": replay_status,
                "replay_body": replay_body[:200],
            },
        ))

        # ------------------------------------------------------------------
        # Variant 2: duplicate_request_replay
        # Send the identical POST request twice in rapid succession.
        # Without nonce or idempotency enforcement the server accepts both,
        # meaning a captured request can be replayed.
        # ------------------------------------------------------------------
        settings_body = {
            "action": "update_setting",
            "key": "redteam_nonce_test",
            "value": uuid.uuid4().hex,
        }

        status_first, body_first, _ = await client.post(
            self.SETTINGS_PATH,
            json_body=settings_body,
        )
        status_second, body_second, _ = await client.post(
            self.SETTINGS_PATH,
            json_body=settings_body,
        )

        if status_first == 200 and status_second == 200:
            v2_status = Status.VULNERABLE
            v2_evidence = (
                f"First POST: {status_first}, Second POST: {status_second} — "
                "both identical requests accepted."
            )
            v2_details = (
                "The API accepted two identical POST requests without nonce or "
                "idempotency key validation. A replay attacker can re-submit "
                "captured state-mutating requests. Implement per-request nonces "
                "or idempotency keys (NIST SP 800-172 3.5.1e)."
            )
        elif status_first == 200 and status_second not in (200,):
            v2_status = Status.DEFENDED
            v2_evidence = (
                f"First POST: {status_first}, Second POST: {status_second} — "
                "duplicate rejected."
            )
            v2_details = (
                f"Server rejected the duplicate request with {status_second}, "
                "indicating replay/idempotency protection is active."
            )
        else:
            # Neither succeeded (e.g. endpoint requires higher privilege) — inconclusive.
            v2_status = Status.PARTIAL
            v2_evidence = (
                f"First POST: {status_first}, Second POST: {status_second} — "
                "endpoint may require elevated privilege; result inconclusive."
            )
            v2_details = (
                "Could not conclusively test idempotency: first request was not "
                f"accepted (status {status_first}). Endpoint may require different "
                "credentials or the key/value pair format differs."
            )

        results.append(self._make_result(
            variant="duplicate_request_replay",
            status=v2_status,
            evidence=v2_evidence,
            details=v2_details,
            request={
                "path": self.SETTINGS_PATH,
                "body": settings_body,
                "note": "Sent twice with identical payload",
            },
            response={
                "first_status": status_first,
                "first_body": body_first[:200],
                "second_status": status_second,
                "second_body": body_second[:200],
            },
        ))

        # ------------------------------------------------------------------
        # Variant 3: expired_token_window
        # Present a JWT with exp = now - 1 (just expired, 1 second ago).
        # Strict implementations must reject it; lenient ones allow a clock
        # skew window that attackers can abuse with recently-captured tokens.
        # ------------------------------------------------------------------
        expired_token = self._expired_jwt()
        exp_status, exp_body, _ = await client.get(
            "/api/ai_chat.php",
            params={"session_id": "redteam-replay"},
            cookies={"eqmon_session": expired_token},
        )

        if exp_status == 200:
            v3_status = Status.VULNERABLE
            v3_evidence = (
                f"Status: {exp_status} — server accepted a token that expired "
                "1 second ago."
            )
            v3_details = (
                "The server accepted a JWT with exp = now-1. This indicates a "
                "permissive clock-skew window that allows replay of recently "
                "expired tokens. Configure leeway to 0 or ≤ 30 seconds and "
                "validate strictly (NIST SP 800-172 3.5.1e)."
            )
        else:
            v3_status = Status.DEFENDED
            v3_evidence = (
                f"Status: {exp_status} — just-expired token correctly rejected."
            )
            v3_details = (
                f"Server returned {exp_status} for a JWT that expired 1 second "
                "ago. Strict expiry validation is enforced."
            )

        results.append(self._make_result(
            variant="expired_token_window",
            status=v3_status,
            evidence=v3_evidence,
            details=v3_details,
            request={
                "path": "/api/ai_chat.php",
                "cookie": "eqmon_session=<JWT exp=now-1>",
                "jwt_claims": {"exp": "now - 1 second", "role": "system-admin"},
            },
            response={"status": exp_status, "body": exp_body[:200]},
        ))

        # ------------------------------------------------------------------
        # Variant 4: captured_request_delayed_replay
        # Make a request, wait 5 seconds, replay the identical request with
        # the same cookies. A server enforcing per-request timestamps or
        # short-lived nonces would reject the second request.
        # ------------------------------------------------------------------
        replay_session_id = f"redteam-delayed-{uuid.uuid4().hex[:8]}"

        status_orig, body_orig, _ = await client.get(
            self.PROTECTED_PATH,
            params={"session_id": replay_session_id},
        )
        saved_cookies_delayed = dict(client._cookies)

        await asyncio.sleep(5)

        status_delayed, body_delayed, _ = await client.get(
            self.PROTECTED_PATH,
            params={"session_id": replay_session_id},
            cookies=saved_cookies_delayed,
        )

        if status_orig == 200 and status_delayed == 200:
            # Both succeed — no timestamp validation; not critical but noteworthy.
            v4_status = Status.PARTIAL
            v4_evidence = (
                f"Original: {status_orig}, Delayed replay (5s): {status_delayed} — "
                "both accepted; no timestamp-based request validation detected."
            )
            v4_details = (
                "The server accepted a replayed request 5 seconds after the "
                "original. No per-request timestamp or nonce validation is in "
                "place. While not immediately critical if sessions expire on "
                "logout, adding request-level replay protection (e.g. signed "
                "timestamps or nonces) would satisfy NIST SP 800-172 3.5.1e "
                "more comprehensively."
            )
        elif status_delayed in (401, 403, 429):
            v4_status = Status.DEFENDED
            v4_evidence = (
                f"Original: {status_orig}, Delayed replay (5s): {status_delayed} — "
                "replay rejected."
            )
            v4_details = (
                f"Server returned {status_delayed} on delayed replay, suggesting "
                "request-level replay protection or rate limiting is active."
            )
        else:
            v4_status = Status.PARTIAL
            v4_evidence = (
                f"Original: {status_orig}, Delayed replay: {status_delayed} — "
                "inconclusive result."
            )
            v4_details = (
                f"Original request returned {status_orig}; delayed replay "
                f"returned {status_delayed}. Could not definitively assess "
                "timestamp-based replay protection."
            )

        results.append(self._make_result(
            variant="captured_request_delayed_replay",
            status=v4_status,
            severity=Severity.MEDIUM,
            evidence=v4_evidence,
            details=v4_details,
            request={
                "path": self.PROTECTED_PATH,
                "session_id": replay_session_id,
                "note": "Same request replayed after 5-second delay with captured cookies",
            },
            response={
                "original_status": status_orig,
                "delayed_status": status_delayed,
                "delayed_body": body_delayed[:200],
            },
        ))

        # ------------------------------------------------------------------
        # Variant 5: cross_session_cookie_replay
        # Login as user A, capture cookie. Establish a new session (user B
        # login or simply a fresh session request), then replay user A's old
        # cookie. A compliant server must track active tokens server-side and
        # reject tokens once a newer login supersedes them (or after logout).
        # ------------------------------------------------------------------
        # Attempt initial login to get a fresh cookie set for "user A".
        login_ok_a = await client.login(
            "redteam-sysadmin@example.com", "RedTeam2026!"
        )
        login_status_a = 200 if login_ok_a else 401
        cookie_a = dict(client._cookies)

        # Initiate a second login (same or different user) to rotate server state.
        login_ok_b = await client.login(
            "redteam-sysadmin@example.com", "RedTeam2026!"
        )
        login_status_b = 200 if login_ok_b else 401

        # Now replay cookie_a (the pre-rotation cookie).
        cross_status, cross_body, _ = await client.get(
            self.PROTECTED_PATH,
            params={"session_id": f"redteam-cross-{uuid.uuid4().hex[:8]}"},
            cookies=cookie_a,
        )

        if login_status_a not in (200, 302) or login_status_b not in (200, 302):
            # Cannot test if login itself failed (credentials or endpoint wrong).
            v5_status = Status.SKIPPED
            v5_evidence = (
                f"Login A: {login_status_a}, Login B: {login_status_b} — "
                "login failed; cross-session replay test skipped."
            )
            v5_details = (
                "Unable to perform cross-session cookie replay test because the "
                "login endpoint did not return a successful response. Verify "
                "test credentials are valid for the target environment."
            )
        elif cross_status == 200:
            v5_status = Status.VULNERABLE
            v5_evidence = (
                f"Login A: {login_status_a}, Login B: {login_status_b}, "
                f"Replay of A's cookie: {cross_status} — old cookie still valid."
            )
            v5_details = (
                "A session cookie captured before a subsequent login remained "
                "valid, indicating the server does not invalidate prior sessions "
                "on new authentication. An attacker with a stolen token retains "
                "access even after the victim re-authenticates. Enforce single "
                "active session or invalidate prior tokens on new login "
                "(NIST SP 800-172 3.5.1e)."
            )
        else:
            v5_status = Status.DEFENDED
            v5_evidence = (
                f"Login A: {login_status_a}, Login B: {login_status_b}, "
                f"Replay of A's cookie: {cross_status} — old cookie rejected."
            )
            v5_details = (
                f"Server returned {cross_status} when replaying a cookie from a "
                "prior session after a subsequent login. Prior session tokens "
                "are correctly invalidated."
            )

        results.append(self._make_result(
            variant="cross_session_cookie_replay",
            status=v5_status,
            evidence=v5_evidence,
            details=v5_details,
            request={
                "step1": "POST /api/auth/login → capture cookie_a",
                "step2": "POST /api/auth/login → establish new session",
                "step3": f"GET {self.PROTECTED_PATH} with cookie_a (replay)",
            },
            response={
                "login_a_status": login_status_a,
                "login_b_status": login_status_b,
                "replay_status": cross_status,
                "replay_body": cross_body[:200],
            },
        ))

        return results
