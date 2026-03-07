"""PCI DSS 4.0 Requirement 7 — Access Restriction.

Verifies that access to cardholder data is restricted on a need-to-know
basis, that default-deny policies are enforced, and that inactive
accounts with CDE access are disabled.
"""

import os
import re
from datetime import datetime, timedelta

from redteam.base import Attack, AttackResult, Severity, Status


class PCIAccessControlAttack(Attack):
    name = "compliance.pci_access_control"
    category = "compliance"
    severity = Severity.HIGH
    description = "PCI DSS 4.0 Req 7 — Verify access restriction to cardholder data"

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        # ----------------------------------------------------------------
        # 1. Default deny check — unauthenticated access must be rejected
        # ----------------------------------------------------------------
        endpoints = self._get_test_endpoints()
        http_methods = ["GET", "POST", "PUT", "DELETE"]
        denied_count = 0
        total_checks = 0
        findings: list[str] = []

        for ep in endpoints:
            for method in http_methods:
                total_checks += 1
                try:
                    if method == "GET":
                        status_code, body, headers = await client.get(ep, cookies={})
                    elif method == "POST":
                        status_code, body, headers = await client.post(
                            ep, json_body={}, cookies={},
                        )
                    elif method == "PUT":
                        status_code, body, headers = await client.post(
                            ep, json_body={"_method": "PUT"}, cookies={},
                        )
                    elif method == "DELETE":
                        status_code, body, headers = await client.post(
                            ep, json_body={"_method": "DELETE"}, cookies={},
                        )
                    else:
                        continue

                    if status_code in (401, 403):
                        denied_count += 1
                    else:
                        findings.append(
                            f"{method} {ep} returned {status_code} "
                            f"(expected 401/403)"
                        )
                except Exception as exc:
                    findings.append(f"{method} {ep} error: {exc}")

        if total_checks == 0:
            deny_status = Status.ERROR
            detail = "No endpoints available to test default-deny policy."
        elif denied_count == total_checks:
            deny_status = Status.DEFENDED
            detail = (
                f"All {total_checks} unauthenticated requests were denied (401/403). "
                "Default-deny policy is enforced."
            )
        elif denied_count > 0:
            deny_status = Status.PARTIAL
            detail = (
                f"{denied_count}/{total_checks} requests denied. "
                f"Some endpoints allow unauthenticated access: "
                + "; ".join(findings[:5])
            )
        else:
            deny_status = Status.VULNERABLE
            detail = (
                f"No unauthenticated requests were denied ({total_checks} tested). "
                "Default-deny is NOT enforced. PCI DSS Req 7.2.3 requires "
                "default 'deny all' unless explicitly allowed."
            )

        results.append(self._make_result(
            variant="default_deny_check",
            status=deny_status,
            severity=Severity.CRITICAL,
            evidence=(
                f"Denied: {denied_count}/{total_checks}, "
                f"Findings: {findings[:5]}"
            ),
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 2. Excessive privileges — users with broad roles and no activity
        # ----------------------------------------------------------------
        try:
            import psycopg2
            db_pass = os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")
            conn = psycopg2.connect(
                host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
            )
            cur = conn.cursor()

            # Find users with admin/superuser roles
            cur.execute("""
                SELECT u.username, u.email, u.role, u.last_login, u.is_active
                FROM users u
                WHERE u.role IN ('admin', 'superuser', 'super_admin', 'sysadmin',
                                 'system_admin', 'root', 'owner')
                  AND u.is_active = TRUE
                ORDER BY u.last_login ASC NULLS FIRST;
            """)
            admin_users = cur.fetchall()

            # Flag admins with no login in 90 days
            ninety_days_ago = datetime.utcnow() - timedelta(days=90)
            stale_admins = []
            active_admins = []
            for username, email, role, last_login, is_active in admin_users:
                if last_login is None or last_login < ninety_days_ago:
                    stale_admins.append((username, role, str(last_login)))
                else:
                    active_admins.append((username, role))

            conn.close()

            if stale_admins:
                priv_status = Status.VULNERABLE
                detail = (
                    f"Found {len(stale_admins)} admin account(s) with no login in 90+ days "
                    f"that still have active privileges: "
                    f"{[(u, r) for u, r, _ in stale_admins]}. "
                    "PCI DSS Req 7.2.5 requires periodic review and revocation of "
                    "unnecessary privileges."
                )
            elif admin_users:
                priv_status = Status.DEFENDED
                detail = (
                    f"All {len(admin_users)} admin accounts have recent activity. "
                    "No excessive privilege concerns detected."
                )
            else:
                priv_status = Status.DEFENDED
                detail = "No admin-level accounts found in user table."

            evidence = (
                f"Admin users: {len(admin_users)}, "
                f"Stale (90+ days): {len(stale_admins)}, "
                f"Active: {len(active_admins)}"
            )

        except ImportError:
            priv_status = Status.ERROR
            detail = "psycopg2 not installed — cannot query for excessive privileges."
            evidence = "psycopg2 missing"
        except Exception as exc:
            priv_status = Status.ERROR
            detail = f"Excessive privilege check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="excessive_privileges",
            status=priv_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 3. Inactive accounts with CDE access still enabled
        # ----------------------------------------------------------------
        try:
            import psycopg2
            db_pass = os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")
            conn = psycopg2.connect(
                host="localhost", dbname="eqmon", user="eqmon", password=db_pass,
            )
            cur = conn.cursor()

            ninety_days_ago = datetime.utcnow() - timedelta(days=90)

            cur.execute("""
                SELECT username, email, role, last_login, is_active
                FROM users
                WHERE is_active = TRUE
                  AND (last_login IS NULL OR last_login < %s)
                ORDER BY last_login ASC NULLS FIRST;
            """, (ninety_days_ago,))
            inactive_accounts = cur.fetchall()
            conn.close()

            if inactive_accounts:
                inactive_status = Status.VULNERABLE
                detail = (
                    f"Found {len(inactive_accounts)} active account(s) with no login in "
                    f"90+ days: {[(u, r, str(ll)) for u, _, r, ll, _ in inactive_accounts[:10]]}. "
                    "PCI DSS Req 8.2.6 requires disabling accounts inactive for 90 days."
                )
                evidence = (
                    f"Inactive accounts: {len(inactive_accounts)}, "
                    f"Sample: {[(u, str(ll)) for u, _, _, ll, _ in inactive_accounts[:5]]}"
                )
            else:
                inactive_status = Status.DEFENDED
                detail = (
                    "No active accounts found with 90+ days of inactivity. "
                    "Account lifecycle management appears compliant."
                )
                evidence = "Query returned 0 inactive accounts"

        except ImportError:
            inactive_status = Status.ERROR
            detail = "psycopg2 not installed — cannot check for inactive accounts."
            evidence = "psycopg2 missing"
        except Exception as exc:
            inactive_status = Status.ERROR
            detail = f"Inactive account check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="inactive_accounts",
            status=inactive_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
        ))

        return results
