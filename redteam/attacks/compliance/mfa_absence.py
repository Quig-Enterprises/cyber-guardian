"""MFA absence detection — NIST SP 800-171 Control 3.5.3.

Verifies that multi-factor authentication is required for local and
network access to privileged accounts and for network access to
non-privileged accounts.
"""

from redteam.base import Attack, AttackResult, Severity, Status


class MFAAbsenceAttack(Attack):
    name = "compliance.mfa_absence"
    category = "compliance"
    severity = Severity.CRITICAL
    description = (
        "NIST 3.5.3 — Verify multi-factor authentication is enforced "
        "for privileged and non-privileged account access"
    )

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. Login without MFA challenge (non-privileged)
        # ----------------------------------------------------------------
        # Attempt a standard login. If the server returns a session token
        # without requiring a second factor, MFA is absent.
        status_code, body, headers = await client.post(
            "/api/auth/login.php",
            json_body={
                "email": "redteam-viewer@test.com",
                "password": "RedTeamV!ewer2026!",
            },
            cookies={},
        )

        # If login succeeds (200 + cookie) without any MFA prompt, it is vulnerable.
        got_session = "eqmon_session" in str(headers) or status_code == 200
        mfa_prompted = "mfa" in body.lower() or "two_factor" in body.lower() or "otp" in body.lower()

        if got_session and not mfa_prompted:
            login_status = Status.VULNERABLE
            detail = (
                f"Login returned {status_code} with session cookie and no MFA challenge. "
                "NIST 3.5.3 requires MFA for network access to non-privileged accounts."
            )
        elif mfa_prompted:
            login_status = Status.DEFENDED
            detail = f"Login returned MFA challenge as expected (status {status_code})."
        else:
            login_status = Status.PARTIAL
            detail = f"Login returned {status_code}. No clear MFA prompt detected."

        results.append(self._make_result(
            variant="login_no_mfa",
            status=login_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, MFA prompted: {mfa_prompted}, Body: {body[:300]}",
            details=detail,
            request={"endpoint": "/api/auth/login.php", "role": "viewer"},
            response={"status": status_code, "body": body[:300]},
        ))

        # ----------------------------------------------------------------
        # 2. Privileged (admin) login without MFA
        # ----------------------------------------------------------------
        status_code, body, headers = await client.post(
            "/api/auth/login.php",
            json_body={
                "email": "redteam-sysadmin@test.com",
                "password": "RedTeam$ysAdmin2026!",
            },
            cookies={},
        )

        got_session = "eqmon_session" in str(headers) or status_code == 200
        mfa_prompted = "mfa" in body.lower() or "two_factor" in body.lower() or "otp" in body.lower()

        if got_session and not mfa_prompted:
            admin_status = Status.VULNERABLE
            detail = (
                f"Admin login returned {status_code} with session cookie and no MFA challenge. "
                "NIST 3.5.3 requires MFA for all privileged account access."
            )
        elif mfa_prompted:
            admin_status = Status.DEFENDED
            detail = f"Admin login returned MFA challenge as expected (status {status_code})."
        else:
            admin_status = Status.PARTIAL
            detail = f"Admin login returned {status_code}. No clear MFA prompt detected."

        results.append(self._make_result(
            variant="privileged_no_mfa",
            status=admin_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, MFA prompted: {mfa_prompted}, Body: {body[:300]}",
            details=detail,
            request={"endpoint": "/api/auth/login.php", "role": "system-admin"},
            response={"status": status_code, "body": body[:300]},
        ))

        # ----------------------------------------------------------------
        # 3. Password reset flow without MFA
        # ----------------------------------------------------------------
        # Attempt to trigger a password reset. If no second factor is
        # required to complete the reset, it is a compliance gap.
        status_code, body, headers = await client.post(
            "/api/auth/login.php",
            json_body={
                "action": "reset_password",
                "email": "redteam-viewer@test.com",
            },
            cookies={},
        )

        mfa_prompted = "mfa" in body.lower() or "two_factor" in body.lower() or "otp" in body.lower()
        reset_accepted = status_code in (200, 202)

        if reset_accepted and not mfa_prompted:
            reset_status = Status.VULNERABLE
            detail = (
                f"Password reset accepted (status {status_code}) without MFA verification. "
                "An attacker with email access alone could reset credentials."
            )
        elif mfa_prompted:
            reset_status = Status.DEFENDED
            detail = f"Password reset required MFA verification (status {status_code})."
        elif status_code in (404, 405):
            reset_status = Status.VULNERABLE
            detail = (
                f"Password reset endpoint returned {status_code}. "
                "No password reset flow exists, which also means no MFA on recovery."
            )
        else:
            reset_status = Status.PARTIAL
            detail = f"Password reset returned {status_code}. Unable to determine MFA status."

        results.append(self._make_result(
            variant="password_reset_no_mfa",
            status=reset_status,
            severity=Severity.HIGH,
            evidence=f"Status: {status_code}, MFA prompted: {mfa_prompted}, Body: {body[:300]}",
            details=detail,
            request={"endpoint": "/api/auth/login.php", "action": "reset_password"},
            response={"status": status_code, "body": body[:300]},
        ))

        return results
