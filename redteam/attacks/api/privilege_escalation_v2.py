"""Privilege escalation via role boundary violations — NIST SP 800-171 Control 3.1.7.

Tests whether a viewer-role user can access admin-only endpoints or
manipulate their role assignment via parameter tampering.
"""

from redteam.base import Attack, AttackResult, Severity, Status


class PrivilegeEscalationV2Attack(Attack):
    name = "api.privilege_escalation_v2"
    category = "api"
    severity = Severity.HIGH
    description = (
        "NIST 3.1.7 — Verify that non-privileged users cannot access "
        "privileged functions or tamper with role assignments"
    )

    ADMIN_ENDPOINTS = [
        ("/api/admin/settings.php", "GET", "Admin settings read"),
        ("/api/admin/users.php", "GET", "User management list"),
    ]

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # Login as viewer first
        login_ok = await client.login(
            "redteam-viewer@example.com", "RedTeamV!ewer2026!"
        )
        if not login_ok:
            results.append(self._make_result(
                variant="viewer_admin_endpoints",
                status=Status.ERROR,
                evidence="Viewer login failed — cannot test privilege escalation.",
                details="Could not authenticate as viewer to test role boundaries.",
            ))
            return results

        viewer_cookies = dict(client._cookies)

        # ----------------------------------------------------------------
        # 1. Viewer accessing admin endpoints
        # ----------------------------------------------------------------
        endpoint_results = []
        any_vulnerable = False
        all_defended = True

        for path, method, label in self.ADMIN_ENDPOINTS:
            if method == "GET":
                status_code, body, headers = await client.get(
                    path, cookies=viewer_cookies
                )
            else:
                status_code, body, headers = await client.post(
                    path, json_body={}, cookies=viewer_cookies
                )

            if status_code == 200:
                any_vulnerable = True
                all_defended = False
                endpoint_results.append(f"{label} ({path}): {status_code} VULNERABLE")
            elif status_code in (401, 403):
                endpoint_results.append(f"{label} ({path}): {status_code} DEFENDED")
            else:
                all_defended = False
                endpoint_results.append(f"{label} ({path}): {status_code} UNKNOWN")

        if any_vulnerable:
            ep_status = Status.VULNERABLE
            detail = (
                "Viewer role can access admin endpoints. "
                "Role-based access control is not enforced on admin routes."
            )
        elif all_defended:
            ep_status = Status.DEFENDED
            detail = "All admin endpoints correctly rejected viewer role access."
        else:
            ep_status = Status.PARTIAL
            detail = "Mixed results across admin endpoints."

        results.append(self._make_result(
            variant="viewer_admin_endpoints",
            status=ep_status,
            severity=Severity.HIGH,
            evidence="\n".join(endpoint_results),
            details=detail,
            request={"role": "viewer", "endpoints_tested": len(self.ADMIN_ENDPOINTS)},
            response={"results": endpoint_results},
        ))

        # ----------------------------------------------------------------
        # 2. Viewer attempting user management (POST to users endpoint)
        # ----------------------------------------------------------------
        status_code, body, headers = await client.post(
            "/api/admin/users.php",
            json_body={
                "action": "create",
                "email": "redteam-escalation-test@example.com",
                "role": "system-admin",
                "name": "RedTeam Escalation Test",
            },
            cookies=viewer_cookies,
        )

        if status_code in (401, 403):
            mgmt_status = Status.DEFENDED
            detail = f"Viewer POST to /api/admin/users.php returned {status_code} — properly denied."
        elif status_code == 200:
            mgmt_status = Status.VULNERABLE
            detail = (
                "Viewer role successfully POSTed to user management endpoint (200). "
                "A viewer can create admin accounts — critical privilege escalation."
            )
        else:
            mgmt_status = Status.PARTIAL
            detail = f"Viewer POST to /api/admin/users.php returned {status_code}."

        results.append(self._make_result(
            variant="viewer_user_management",
            status=mgmt_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:300]}",
            details=detail,
            request={
                "method": "POST",
                "path": "/api/admin/users.php",
                "role": "viewer",
                "action": "create user with system-admin role",
            },
            response={"status": status_code, "body": body[:300]},
        ))

        # ----------------------------------------------------------------
        # 3. Role parameter tampering in login request
        # ----------------------------------------------------------------
        # Attempt to include a role field in the login body to see if the
        # server assigns the requested role instead of the DB-stored role.
        status_code, body, headers = await client.post(
            "/api/auth/login.php",
            json_body={
                "email": "redteam-viewer@example.com",
                "password": "RedTeamV!ewer2026!",
                "role": "system-admin",
            },
            cookies={},
        )

        # Check if the returned JWT (if any) has the tampered role
        tampered_role = False
        if status_code == 200:
            try:
                import jwt as pyjwt
                # Extract token from Set-Cookie header or response body
                token = None
                for key, val in headers.items():
                    if key.lower() == "set-cookie" and "eqmon_session=" in val:
                        token = val.split("eqmon_session=")[1].split(";")[0]
                        break
                if token:
                    claims = pyjwt.decode(token, options={"verify_signature": False})
                    if claims.get("role") == "system-admin":
                        tampered_role = True
            except Exception:
                pass

        if tampered_role:
            tamper_status = Status.VULNERABLE
            detail = (
                "Login accepted role='system-admin' from request body. "
                "Server assigns JWT role from client input instead of database. "
                "Critical privilege escalation via parameter tampering."
            )
        elif status_code == 200:
            tamper_status = Status.DEFENDED
            detail = (
                "Login succeeded but server ignored the role parameter in request body. "
                "Role is correctly assigned from the database."
            )
        else:
            tamper_status = Status.PARTIAL
            detail = f"Login with role tampering returned {status_code}."

        results.append(self._make_result(
            variant="role_parameter_tampering",
            status=tamper_status,
            severity=Severity.CRITICAL,
            evidence=(
                f"Status: {status_code}, Role tampered in JWT: {tampered_role}, "
                f"Body: {body[:200]}"
            ),
            details=detail,
            request={"email": "viewer", "injected_role": "system-admin"},
            response={"status": status_code, "role_accepted": tampered_role},
        ))

        return results
