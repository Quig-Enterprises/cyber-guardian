"""Unauthenticated admin settings access — NIST SP 800-171 Control 3.1.1.

Verifies that access to admin configuration endpoints is properly
restricted to authenticated users with appropriate roles.
"""

from redteam.base import Attack, AttackResult, Severity, Status


class UnauthAdminSettingsAttack(Attack):
    name = "api.unauth_admin_settings"
    category = "api"
    severity = Severity.CRITICAL
    description = (
        "NIST 3.1.1 — Verify admin settings endpoints enforce "
        "authentication and role-based authorization"
    )

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. Read settings without any authentication
        # ----------------------------------------------------------------
        status_code, body, headers = await client.get(
            "/api/admin/settings.php",
            cookies={},
        )

        if status_code == 401 or status_code == 403:
            read_status = Status.DEFENDED
            detail = f"Unauthenticated GET returned {status_code} as expected."
        elif status_code == 200:
            read_status = Status.VULNERABLE
            detail = (
                f"Unauthenticated GET returned 200 with settings data. "
                "Admin configuration is exposed without authentication."
            )
        else:
            read_status = Status.PARTIAL
            detail = f"Unauthenticated GET returned unexpected status {status_code}."

        results.append(self._make_result(
            variant="read_settings_no_auth",
            status=read_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=detail,
            request={"method": "GET", "path": "/api/admin/settings.php", "cookies": "none"},
            response={"status": status_code, "body": body[:300]},
        ))

        # ----------------------------------------------------------------
        # 2. Write settings without any authentication
        # ----------------------------------------------------------------
        status_code, body, headers = await client.post(
            "/api/admin/settings.php",
            json_body={
                "action": "update",
                "settings": {"redteam_test": "should_be_rejected"},
            },
            cookies={},
        )

        if status_code == 401 or status_code == 403:
            write_status = Status.DEFENDED
            detail = f"Unauthenticated POST returned {status_code} as expected."
        elif status_code == 200:
            write_status = Status.VULNERABLE
            detail = (
                f"Unauthenticated POST returned 200. "
                "Admin settings can be modified without authentication."
            )
        else:
            write_status = Status.PARTIAL
            detail = f"Unauthenticated POST returned unexpected status {status_code}."

        results.append(self._make_result(
            variant="write_settings_no_auth",
            status=write_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=detail,
            request={"method": "POST", "path": "/api/admin/settings.php", "cookies": "none"},
            response={"status": status_code, "body": body[:300]},
        ))

        # ----------------------------------------------------------------
        # 3. Read settings with viewer role (wrong role)
        # ----------------------------------------------------------------
        # Login as viewer first
        login_ok = await client.login(
            "redteam-viewer@test.com", "RedTeamV!ewer2026!"
        )

        if not login_ok:
            results.append(self._make_result(
                variant="read_settings_wrong_role",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                evidence="Viewer login failed — cannot test role enforcement.",
                details="Could not authenticate as viewer to test role-based access.",
            ))
            return results

        viewer_cookies = dict(client._cookies)

        status_code, body, headers = await client.get(
            "/api/admin/settings.php",
            cookies=viewer_cookies,
        )

        if status_code == 403:
            role_status = Status.DEFENDED
            detail = f"Viewer GET returned 403 — role enforcement is working."
        elif status_code == 401:
            role_status = Status.DEFENDED
            detail = f"Viewer GET returned 401 — treated as unauthenticated."
        elif status_code == 200:
            role_status = Status.VULNERABLE
            detail = (
                f"Viewer GET returned 200 with admin settings. "
                "Viewer role can read admin configuration — role enforcement missing."
            )
        else:
            role_status = Status.PARTIAL
            detail = f"Viewer GET returned unexpected status {status_code}."

        results.append(self._make_result(
            variant="read_settings_wrong_role",
            status=role_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=detail,
            request={"method": "GET", "path": "/api/admin/settings.php", "role": "viewer"},
            response={"status": status_code, "body": body[:300]},
        ))

        return results
