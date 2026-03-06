"""HTTP Security Headers analysis for any web target.

Checks for the presence and correct configuration of security-related
HTTP response headers that protect against common web attacks.

Evaluation:
- Missing Content-Security-Policy -> VULNERABLE
- Missing Strict-Transport-Security -> VULNERABLE
- Missing X-Frame-Options -> VULNERABLE (clickjacking)
- Missing X-Content-Type-Options: nosniff -> VULNERABLE (MIME sniffing)
- Missing Referrer-Policy -> VULNERABLE
- Missing Permissions-Policy / Feature-Policy -> VULNERABLE
- Server header with version info -> INFO
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class SecurityHeadersAttack(Attack):
    """Analyze HTTP security headers on any web target."""

    name = "web.security_headers"
    category = "web"
    severity = Severity.LOW
    description = "HTTP security header presence and configuration analysis"
    target_types = {"generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all security header checks against the homepage."""
        results = []

        # Fetch homepage headers once, reuse for all checks
        try:
            status_code, body, headers = await client.get("/", cookies={})
            self._headers = headers
            self._status_code = status_code
        except Exception as e:
            return [self._make_result(
                variant="fetch_headers",
                status=Status.ERROR,
                details=f"Failed to fetch homepage: {e}",
            )]

        results.append(self._check_csp())
        results.append(self._check_hsts())
        results.append(self._check_x_frame_options())
        results.append(self._check_x_content_type_options())
        results.append(self._check_referrer_policy())
        results.append(self._check_permissions_policy())
        results.append(self._check_server_header())

        return results

    def _check_csp(self) -> AttackResult:
        """Check for Content-Security-Policy header."""
        try:
            csp = self._headers.get("Content-Security-Policy", "")
            if csp:
                return self._make_result(
                    variant="content_security_policy",
                    status=Status.DEFENDED,
                    evidence=f"CSP present: {csp[:200]}",
                    details="Content-Security-Policy header is set",
                    response={"Content-Security-Policy": csp[:500]},
                )
            else:
                return self._make_result(
                    variant="content_security_policy",
                    status=Status.VULNERABLE,
                    evidence="Content-Security-Policy header missing",
                    details="No CSP header; the site is vulnerable to XSS and data injection attacks",
                    response={"Content-Security-Policy": "missing"},
                )
        except Exception as e:
            return self._make_result(
                variant="content_security_policy",
                status=Status.ERROR,
                details=str(e),
            )

    def _check_hsts(self) -> AttackResult:
        """Check for Strict-Transport-Security header."""
        try:
            hsts = self._headers.get("Strict-Transport-Security", "")
            if not hsts:
                return self._make_result(
                    variant="strict_transport_security",
                    status=Status.VULNERABLE,
                    evidence="Strict-Transport-Security header missing",
                    details="No HSTS; browsers will allow HTTP connections, enabling MITM attacks",
                    response={"Strict-Transport-Security": "missing"},
                )

            # Parse max-age
            max_age = 0
            for part in hsts.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    try:
                        max_age = int(part.split("=", 1)[1])
                    except ValueError:
                        pass

            if max_age < 31536000:
                return self._make_result(
                    variant="strict_transport_security",
                    status=Status.PARTIAL,
                    evidence=f"HSTS max-age={max_age} (< 31536000 / 1 year)",
                    details="HSTS is present but max-age is too short; recommended minimum is 1 year (31536000)",
                    response={"Strict-Transport-Security": hsts},
                )
            else:
                return self._make_result(
                    variant="strict_transport_security",
                    status=Status.DEFENDED,
                    evidence=f"HSTS present with max-age={max_age}",
                    details="Strict-Transport-Security properly configured",
                    response={"Strict-Transport-Security": hsts},
                )
        except Exception as e:
            return self._make_result(
                variant="strict_transport_security",
                status=Status.ERROR,
                details=str(e),
            )

    def _check_x_frame_options(self) -> AttackResult:
        """Check for X-Frame-Options header (clickjacking protection)."""
        try:
            xfo = self._headers.get("X-Frame-Options", "")
            if not xfo:
                # Also check CSP frame-ancestors as a modern alternative
                csp = self._headers.get("Content-Security-Policy", "")
                if "frame-ancestors" in csp.lower():
                    return self._make_result(
                        variant="x_frame_options",
                        status=Status.DEFENDED,
                        evidence="X-Frame-Options missing but CSP frame-ancestors is set",
                        details="Clickjacking protection via CSP frame-ancestors directive",
                        response={"X-Frame-Options": "missing", "CSP": csp[:300]},
                    )
                return self._make_result(
                    variant="x_frame_options",
                    status=Status.VULNERABLE,
                    evidence="X-Frame-Options header missing",
                    details="No clickjacking protection; page can be embedded in iframes on any site",
                    response={"X-Frame-Options": "missing"},
                )

            xfo_upper = xfo.upper().strip()
            if xfo_upper in ("DENY", "SAMEORIGIN"):
                return self._make_result(
                    variant="x_frame_options",
                    status=Status.DEFENDED,
                    evidence=f"X-Frame-Options: {xfo}",
                    details=f"Clickjacking protection active ({xfo_upper})",
                    response={"X-Frame-Options": xfo},
                )
            else:
                return self._make_result(
                    variant="x_frame_options",
                    status=Status.PARTIAL,
                    evidence=f"X-Frame-Options: {xfo} (unexpected value)",
                    details="X-Frame-Options set but value may not provide full protection",
                    response={"X-Frame-Options": xfo},
                )
        except Exception as e:
            return self._make_result(
                variant="x_frame_options",
                status=Status.ERROR,
                details=str(e),
            )

    def _check_x_content_type_options(self) -> AttackResult:
        """Check for X-Content-Type-Options: nosniff."""
        try:
            xcto = self._headers.get("X-Content-Type-Options", "")
            if xcto.lower().strip() == "nosniff":
                return self._make_result(
                    variant="x_content_type_options",
                    status=Status.DEFENDED,
                    evidence="X-Content-Type-Options: nosniff",
                    details="MIME type sniffing protection is active",
                    response={"X-Content-Type-Options": xcto},
                )
            elif xcto:
                return self._make_result(
                    variant="x_content_type_options",
                    status=Status.PARTIAL,
                    evidence=f"X-Content-Type-Options: {xcto} (expected 'nosniff')",
                    details="Header present but unexpected value",
                    response={"X-Content-Type-Options": xcto},
                )
            else:
                return self._make_result(
                    variant="x_content_type_options",
                    status=Status.VULNERABLE,
                    evidence="X-Content-Type-Options header missing",
                    details="No MIME sniffing protection; browsers may interpret files as different content types",
                    response={"X-Content-Type-Options": "missing"},
                )
        except Exception as e:
            return self._make_result(
                variant="x_content_type_options",
                status=Status.ERROR,
                details=str(e),
            )

    def _check_referrer_policy(self) -> AttackResult:
        """Check for Referrer-Policy header."""
        try:
            rp = self._headers.get("Referrer-Policy", "")
            if rp:
                return self._make_result(
                    variant="referrer_policy",
                    status=Status.DEFENDED,
                    evidence=f"Referrer-Policy: {rp}",
                    details="Referrer-Policy is configured",
                    response={"Referrer-Policy": rp},
                )
            else:
                return self._make_result(
                    variant="referrer_policy",
                    status=Status.VULNERABLE,
                    evidence="Referrer-Policy header missing",
                    details="No Referrer-Policy; full URLs may leak via Referer header to third parties",
                    response={"Referrer-Policy": "missing"},
                )
        except Exception as e:
            return self._make_result(
                variant="referrer_policy",
                status=Status.ERROR,
                details=str(e),
            )

    def _check_permissions_policy(self) -> AttackResult:
        """Check for Permissions-Policy or legacy Feature-Policy header."""
        try:
            pp = self._headers.get("Permissions-Policy", "")
            fp = self._headers.get("Feature-Policy", "")
            if pp:
                return self._make_result(
                    variant="permissions_policy",
                    status=Status.DEFENDED,
                    evidence=f"Permissions-Policy: {pp[:200]}",
                    details="Permissions-Policy header is set",
                    response={"Permissions-Policy": pp[:500]},
                )
            elif fp:
                return self._make_result(
                    variant="permissions_policy",
                    status=Status.DEFENDED,
                    evidence=f"Feature-Policy (legacy): {fp[:200]}",
                    details="Legacy Feature-Policy header found; consider migrating to Permissions-Policy",
                    response={"Feature-Policy": fp[:500]},
                )
            else:
                return self._make_result(
                    variant="permissions_policy",
                    status=Status.VULNERABLE,
                    evidence="Neither Permissions-Policy nor Feature-Policy header present",
                    details="No permissions policy; browser features like camera, microphone, geolocation are unrestricted",
                    response={"Permissions-Policy": "missing", "Feature-Policy": "missing"},
                )
        except Exception as e:
            return self._make_result(
                variant="permissions_policy",
                status=Status.ERROR,
                details=str(e),
            )

    def _check_server_header(self) -> AttackResult:
        """Check Server header for information disclosure."""
        try:
            server = self._headers.get("Server", "")
            if not server:
                return self._make_result(
                    variant="server_header",
                    status=Status.DEFENDED,
                    severity=Severity.INFO,
                    evidence="Server header not present",
                    details="Server identity not disclosed in response headers",
                    response={"Server": "missing"},
                )

            # Check if version number is exposed
            import re
            has_version = bool(re.search(r'\d+\.\d+', server))
            if has_version:
                return self._make_result(
                    variant="server_header",
                    status=Status.VULNERABLE,
                    severity=Severity.INFO,
                    evidence=f"Server: {server}",
                    details=f"Server header exposes version information: {server}",
                    response={"Server": server},
                )
            else:
                return self._make_result(
                    variant="server_header",
                    status=Status.DEFENDED,
                    severity=Severity.INFO,
                    evidence=f"Server: {server} (no version)",
                    details=f"Server identified as {server} but no version disclosed",
                    response={"Server": server},
                )
        except Exception as e:
            return self._make_result(
                variant="server_header",
                status=Status.ERROR,
                details=str(e),
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by header checks."""
        pass
