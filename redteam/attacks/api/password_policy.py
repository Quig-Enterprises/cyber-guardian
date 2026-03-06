"""Password policy enforcement — NIST SP 800-171 Controls 3.5.7, 3.5.8.

Verifies that the application enforces minimum password length,
complexity requirements, and rejects commonly-used passwords.
"""

from redteam.base import Attack, AttackResult, Severity, Status


class PasswordPolicyAttack(Attack):
    name = "api.password_policy"
    category = "api"
    severity = Severity.MEDIUM
    description = (
        "NIST 3.5.7/3.5.8 — Verify password complexity, minimum length, "
        "and common password rejection policies"
    )
    target_types = {"eqmon", "wordpress"}

    # Test passwords that SHOULD be rejected by a compliant system
    WEAK_PASSWORDS = [
        ("short_password", "abc123", "6-char password — below minimum length"),
        ("no_complexity", "abcdefghijklmnop", "16-char all-lowercase — no complexity"),
        ("common_password", "password12345678", "Common password with digits appended"),
    ]

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # We need to be authenticated to test password change.
        # Login as the test viewer user.
        login_ok = await client.login(
            "redteam-viewer@test.com", "RedTeamV!ewer2026!"
        )
        if not login_ok:
            # Try testing via registration or password reset if login fails
            for variant_name, weak_pw, description in self.WEAK_PASSWORDS:
                results.append(self._make_result(
                    variant=variant_name,
                    status=Status.ERROR,
                    evidence="Login failed — cannot test password policy via change endpoint.",
                    details=f"Could not authenticate to test: {description}",
                ))
            return results

        auth_cookies = dict(client._cookies)

        for variant_name, weak_pw, description in self.WEAK_PASSWORDS:
            # Try to change password to the weak value
            # Test multiple possible password change endpoints
            tested = False

            # Attempt 1: dedicated password change endpoint
            login_endpoint = self._get_login_endpoint()
            status_code, body, headers = await client.post(
                login_endpoint,
                json_body={
                    "action": "change_password",
                    "current_password": "RedTeamV!ewer2026!",
                    "new_password": weak_pw,
                },
                cookies=auth_cookies,
            )

            if status_code == 404 or status_code == 405:
                # Try admin users endpoint (target-type aware fallback)
                target_type = self._get_target_type()
                if target_type == "wordpress":
                    admin_endpoint = "/wp-json/wp/v2/users/me"
                elif target_type == "generic":
                    admin_endpoint = self._config.get("target", {}).get("generic", {}).get("admin_endpoint", "/api/admin/users")
                else:
                    admin_endpoint = "/api/admin/users.php"
                status_code, body, headers = await client.post(
                    admin_endpoint,
                    json_body={
                        "action": "change_password",
                        "password": weak_pw,
                    },
                    cookies=auth_cookies,
                )

            # Analyze the response
            rejected_indicators = [
                "too short" in body.lower(),
                "complexity" in body.lower(),
                "weak" in body.lower(),
                "requirements" in body.lower(),
                "policy" in body.lower(),
                "minimum" in body.lower(),
                "must contain" in body.lower(),
                status_code == 422,
                status_code == 400 and ("password" in body.lower()),
            ]
            was_rejected = any(rejected_indicators)

            if was_rejected:
                pw_status = Status.DEFENDED
                detail = (
                    f"Weak password rejected (status {status_code}): {description}. "
                    "Password policy is enforced."
                )
            elif status_code == 200 and ("success" in body.lower() or "updated" in body.lower()):
                pw_status = Status.VULNERABLE
                detail = (
                    f"Weak password accepted (status {status_code}): {description}. "
                    f"NIST 3.5.7 requires minimum password complexity. "
                    f"Password '{weak_pw}' should have been rejected."
                )
                # Reset the password back to the original
                await client.post(
                    login_endpoint,
                    json_body={
                        "action": "change_password",
                        "current_password": weak_pw,
                        "new_password": "RedTeamV!ewer2026!",
                    },
                    cookies=auth_cookies,
                )
            elif status_code in (401, 403):
                pw_status = Status.PARTIAL
                detail = (
                    f"Password change returned {status_code} (auth issue). "
                    "Cannot determine if password policy is enforced."
                )
            elif status_code in (404, 405):
                pw_status = Status.VULNERABLE
                detail = (
                    f"No password change endpoint found (status {status_code}). "
                    "Without a password change mechanism, password policy cannot be enforced. "
                    "NIST 3.5.8 requires the ability to enforce password changes."
                )
            else:
                pw_status = Status.PARTIAL
                detail = (
                    f"Password change returned {status_code}. "
                    "Unable to determine if password policy is enforced."
                )

            results.append(self._make_result(
                variant=variant_name,
                status=pw_status,
                severity=Severity.MEDIUM,
                evidence=f"Status: {status_code}, Body: {body[:300]}",
                details=detail,
                request={"weak_password": weak_pw, "description": description},
                response={"status": status_code, "body": body[:300]},
            ))

        return results
