"""WordPress admin area exposure tests.

Checks for unprotected access to wp-admin, admin-ajax.php actions,
the WordPress installer, and upgrade scripts without authentication.
"""

import time

from redteam.base import Attack, AttackResult, Severity, Status


class AdminExposureAttack(Attack):
    name = "wordpress.admin_exposure"
    category = "wordpress"
    severity = Severity.MEDIUM
    description = "WordPress admin area access without proper authentication"
    target_types = {"wordpress"}

    # Admin-ajax actions that should require authentication
    PRIVILEGED_AJAX_ACTIONS = ["save-widget", "delete-post", "wp-ajax-crop-image"]

    async def execute(self, client) -> list[AttackResult]:
        results = []
        results.extend(await self._wp_admin_no_auth(client))
        results.extend(await self._admin_ajax_unauthenticated(client))
        results.append(await self._admin_install(client))
        results.append(await self._admin_upgrade(client))
        return results

    # ------------------------------------------------------------------
    # Variant 1: wp-admin without auth cookies
    # ------------------------------------------------------------------
    async def _wp_admin_no_auth(self, client) -> list[AttackResult]:
        """GET /wp-admin/ with no cookies.

        DEFENDED if redirected to wp-login.php (302).
        VULNERABLE if admin dashboard HTML returned (200 with dashboard markers).
        """
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get(
                f"{client.admin_path}/",
                cookies={},
            )
            duration = (time.monotonic() - start) * 1000
        except Exception as e:
            return [self._make_result(
                variant="wp_admin_no_auth",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception accessing wp-admin without auth",
            )]

        body_lower = body.lower()
        is_redirect = status_code in (301, 302, 303, 307)
        redirect_to_login = is_redirect and "wp-login.php" in headers.get("Location", "")
        has_dashboard = (
            status_code == 200
            and ("dashboard" in body_lower or "wp-admin" in body_lower)
        )

        if redirect_to_login:
            status = Status.DEFENDED
            evidence = f"Redirected to login page (HTTP {status_code})"
        elif has_dashboard:
            status = Status.VULNERABLE
            evidence = "Admin dashboard accessible without authentication"
        elif is_redirect:
            status = Status.DEFENDED
            evidence = f"Redirected (HTTP {status_code}) to: {headers.get('Location', 'unknown')}"
        elif status_code == 403:
            status = Status.DEFENDED
            evidence = "Access forbidden (403) without auth"
        else:
            status = Status.PARTIAL
            evidence = f"Unexpected response: HTTP {status_code}"

        return [self._make_result(
            variant="wp_admin_no_auth",
            status=status,
            evidence=evidence,
            details=f"GET {client.admin_path}/ without cookies returned {status_code}",
            request={"path": f"{client.admin_path}/", "cookies": "none"},
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration,
        )]

    # ------------------------------------------------------------------
    # Variant 2: admin-ajax.php unauthenticated actions
    # ------------------------------------------------------------------
    async def _admin_ajax_unauthenticated(self, client) -> list[AttackResult]:
        """Test admin-ajax.php actions without authentication.

        heartbeat should work unauthenticated (benign).
        State-changing actions (save-widget, delete-post, etc.) should fail.
        VULNERABLE if any privileged action returns a success response.
        """
        results = []

        # First test heartbeat (expected to work, establishes baseline)
        start = time.monotonic()
        try:
            hb_status, hb_body, _ = await client.ajax_post(
                "heartbeat",
                data={"data[wp-auth-check]": "true"},
                authenticated=False,
            )
            hb_duration = (time.monotonic() - start) * 1000
        except Exception as e:
            hb_status = 0
            hb_body = str(e)
            hb_duration = 0

        results.append(self._make_result(
            variant="admin_ajax_heartbeat_baseline",
            status=Status.DEFENDED,
            severity=Severity.INFO,
            evidence=f"Heartbeat returned {hb_status} (baseline for ajax tests)",
            details="Heartbeat is expected to work without auth; used as test baseline",
            request={"action": "heartbeat", "authenticated": False},
            response={"status": hb_status, "body": hb_body[:200]},
            duration_ms=hb_duration,
        ))

        # Test privileged actions that should require auth
        for action in self.PRIVILEGED_AJAX_ACTIONS:
            start = time.monotonic()
            try:
                status_code, body, headers = await client.ajax_post(
                    action,
                    authenticated=False,
                )
                duration = (time.monotonic() - start) * 1000
            except Exception as e:
                results.append(self._make_result(
                    variant=f"admin_ajax_{action}",
                    status=Status.ERROR,
                    evidence=str(e),
                    details=f"Exception testing unauthenticated {action}",
                ))
                continue

            # WordPress returns "0" or "-1" for unauthorized ajax calls
            body_stripped = body.strip()
            action_succeeded = (
                status_code == 200
                and body_stripped not in ("0", "-1", "")
                and "not allowed" not in body.lower()
                and "permission" not in body.lower()
            )

            results.append(self._make_result(
                variant=f"admin_ajax_{action}",
                status=Status.VULNERABLE if action_succeeded else Status.DEFENDED,
                evidence=(
                    f"Privileged action '{action}' succeeded without auth"
                    if action_succeeded
                    else f"Action '{action}' correctly denied (response: {body_stripped[:80]})"
                ),
                details=(
                    f"POST admin-ajax.php?action={action} without auth: "
                    f"status={status_code}, body={body_stripped[:100]}"
                ),
                request={"action": action, "authenticated": False},
                response={"status": status_code, "body": body_stripped[:200]},
                duration_ms=duration,
            ))

        return results

    # ------------------------------------------------------------------
    # Variant 3: WordPress installer access
    # ------------------------------------------------------------------
    async def _admin_install(self, client) -> AttackResult:
        """GET /wp-admin/install.php without auth.

        VULNERABLE if the WordPress installer is accessible.
        DEFENDED if redirected, forbidden, or not found.
        """
        path = f"{client.admin_path}/install.php"
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000
        except Exception as e:
            return self._make_result(
                variant="admin_install",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception accessing install.php",
            )

        body_lower = body.lower()
        is_installer = (
            status_code == 200
            and ("install" in body_lower or "setup" in body_lower or "database" in body_lower)
            and "already installed" not in body_lower
        )
        already_installed = status_code == 200 and "already installed" in body_lower
        is_blocked = status_code in (301, 302, 303, 403, 404)

        if is_installer:
            status = Status.VULNERABLE
            evidence = "WordPress installer accessible - site can be reinstalled"
        elif already_installed:
            status = Status.DEFENDED
            evidence = "install.php shows 'already installed' message (non-exploitable)"
        elif is_blocked:
            status = Status.DEFENDED
            evidence = f"install.php blocked (HTTP {status_code})"
        else:
            status = Status.DEFENDED
            evidence = f"install.php returned {status_code} - not exploitable"

        return self._make_result(
            variant="admin_install",
            status=status,
            evidence=evidence,
            details=f"GET {path} returned {status_code}",
            request={"path": path, "cookies": "none"},
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 4: WordPress upgrade script access
    # ------------------------------------------------------------------
    async def _admin_upgrade(self, client) -> AttackResult:
        """GET /wp-admin/upgrade.php without auth.

        VULNERABLE if upgrade script accessible without authentication.
        DEFENDED if redirected to login or blocked.
        """
        path = f"{client.admin_path}/upgrade.php"
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000
        except Exception as e:
            return self._make_result(
                variant="admin_upgrade",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception accessing upgrade.php",
            )

        is_redirect_login = (
            status_code in (301, 302, 303)
            and "wp-login.php" in headers.get("Location", "")
        )
        is_accessible = (
            status_code == 200
            and ("upgrade" in body.lower() or "update" in body.lower())
        )

        if is_redirect_login:
            status = Status.DEFENDED
            evidence = "upgrade.php redirects to login"
        elif status_code == 403:
            status = Status.DEFENDED
            evidence = "upgrade.php blocked (403)"
        elif is_accessible:
            status = Status.VULNERABLE
            evidence = "upgrade.php accessible without authentication"
        else:
            status = Status.DEFENDED
            evidence = f"upgrade.php returned {status_code}"

        return self._make_result(
            variant="admin_upgrade",
            status=status,
            evidence=evidence,
            details=f"GET {path} without auth returned {status_code}",
            request={"path": path, "cookies": "none"},
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration,
        )
