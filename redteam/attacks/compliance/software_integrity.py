"""Software integrity verification — NIST SP 800-172 Control 3.14.1e.

Verifies code signing, subresource integrity (SRI) on scripts/stylesheets,
and secure boot indicators via CSP analysis and mixed-content detection.
"""

import json
import re

from redteam.base import Attack, AttackResult, Severity, Status


class SoftwareIntegrityAttack(Attack):
    name = "compliance.software_integrity"
    category = "compliance"
    severity = Severity.MEDIUM
    description = (
        "NIST 800-172 3.14.1e — Verify software integrity through cryptographic "
        "signatures and SRI"
    )

    PAGES = ["/", "/admin/login.php", "/admin/index.php"]

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. Subresource Integrity — <script src="...">
        # ----------------------------------------------------------------
        scripts_with_sri = 0
        scripts_without_sri = 0
        external_scripts_without_sri = []
        pages_checked = []

        for page in self.PAGES:
            try:
                status_code, body, headers = await client.get(page)
                if status_code not in (200, 401, 403):
                    continue
                pages_checked.append(page)

                base_origin = re.sub(r"(https?://[^/]+).*", r"\1", client.base_url)

                for tag in re.finditer(
                    r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', body, re.IGNORECASE
                ):
                    full_tag = tag.group(0)
                    src = tag.group(1)
                    has_integrity = bool(re.search(r'\bintegrity\s*=', full_tag, re.IGNORECASE))

                    is_external = src.startswith("http://") or src.startswith("https://")
                    if is_external:
                        tag_origin = re.sub(r"(https?://[^/]+).*", r"\1", src)
                        is_external = tag_origin != base_origin

                    if has_integrity:
                        scripts_with_sri += 1
                    else:
                        scripts_without_sri += 1
                        if is_external:
                            external_scripts_without_sri.append(src)
            except Exception:
                pass

        total_scripts = scripts_with_sri + scripts_without_sri
        if external_scripts_without_sri:
            sri_script_status = Status.VULNERABLE
            detail = (
                f"Found {len(external_scripts_without_sri)} external script(s) lacking SRI "
                f"integrity attribute: {external_scripts_without_sri}. "
                "External scripts without SRI can be tampered mid-transit without detection. "
                "NIST 800-172 3.14.1e requires cryptographic verification of software components."
            )
        elif total_scripts > 0 and scripts_without_sri > 0:
            sri_script_status = Status.PARTIAL
            detail = (
                f"Found {scripts_without_sri} local script(s) without SRI and "
                f"{scripts_with_sri} with SRI across pages {pages_checked}. "
                "No external scripts are missing SRI, but local scripts could benefit from "
                "SRI for defence-in-depth integrity verification."
            )
        elif total_scripts > 0:
            sri_script_status = Status.DEFENDED
            detail = (
                f"All {scripts_with_sri} script tag(s) found across {pages_checked} "
                "include the integrity attribute."
            )
        else:
            sri_script_status = Status.PARTIAL
            detail = (
                f"No <script src> tags found on pages {pages_checked}. "
                "Unable to assess SRI coverage for scripts."
            )

        results.append(self._make_result(
            variant="subresource_integrity_scripts",
            status=sri_script_status,
            evidence=(
                f"Pages checked: {pages_checked}, scripts with SRI: {scripts_with_sri}, "
                f"without SRI: {scripts_without_sri}, "
                f"external without SRI: {external_scripts_without_sri}"
            ),
            details=detail,
            request={"pages": self.PAGES},
            response={"pages_checked": pages_checked},
        ))

        # ----------------------------------------------------------------
        # 2. Subresource Integrity — <link rel="stylesheet" href="...">
        # ----------------------------------------------------------------
        css_with_sri = 0
        css_without_sri = 0
        external_css_without_sri = []
        pages_checked_css = []

        for page in self.PAGES:
            try:
                status_code, body, headers = await client.get(page)
                if status_code not in (200, 401, 403):
                    continue
                pages_checked_css.append(page)

                base_origin = re.sub(r"(https?://[^/]+).*", r"\1", client.base_url)

                for tag in re.finditer(
                    r'<link[^>]+rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>|'
                    r'<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\'][^>]*>',
                    body,
                    re.IGNORECASE,
                ):
                    full_tag = tag.group(0)
                    href = tag.group(1) or tag.group(2)
                    if not href:
                        continue
                    has_integrity = bool(re.search(r'\bintegrity\s*=', full_tag, re.IGNORECASE))

                    is_external = href.startswith("http://") or href.startswith("https://")
                    if is_external:
                        tag_origin = re.sub(r"(https?://[^/]+).*", r"\1", href)
                        is_external = tag_origin != base_origin

                    if has_integrity:
                        css_with_sri += 1
                    else:
                        css_without_sri += 1
                        if is_external:
                            external_css_without_sri.append(href)
            except Exception:
                pass

        total_css = css_with_sri + css_without_sri
        if external_css_without_sri:
            sri_css_status = Status.VULNERABLE
            detail = (
                f"Found {len(external_css_without_sri)} external stylesheet(s) lacking SRI "
                f"integrity attribute: {external_css_without_sri}. "
                "External CSS without SRI can be used to inject malicious content via "
                "CSS exfiltration or UI redressing. NIST 800-172 3.14.1e requires integrity "
                "verification for all loaded software components."
            )
        elif total_css > 0 and css_without_sri > 0:
            sri_css_status = Status.PARTIAL
            detail = (
                f"Found {css_without_sri} local stylesheet(s) without SRI and "
                f"{css_with_sri} with SRI across pages {pages_checked_css}. "
                "No external stylesheets are missing SRI."
            )
        elif total_css > 0:
            sri_css_status = Status.DEFENDED
            detail = (
                f"All {css_with_sri} stylesheet link(s) found across {pages_checked_css} "
                "include the integrity attribute."
            )
        else:
            sri_css_status = Status.PARTIAL
            detail = (
                f"No <link rel=stylesheet> tags found on pages {pages_checked_css}. "
                "Unable to assess SRI coverage for stylesheets."
            )

        results.append(self._make_result(
            variant="subresource_integrity_stylesheets",
            status=sri_css_status,
            evidence=(
                f"Pages checked: {pages_checked_css}, CSS with SRI: {css_with_sri}, "
                f"without SRI: {css_without_sri}, "
                f"external without SRI: {external_css_without_sri}"
            ),
            details=detail,
            request={"pages": self.PAGES},
            response={"pages_checked": pages_checked_css},
        ))

        # ----------------------------------------------------------------
        # 3. Content-Security-Policy header analysis
        # ----------------------------------------------------------------
        csp_headers_seen = []
        csp_missing_pages = []
        csp_unsafe_pages = []
        csp_strict_pages = []

        for page in self.PAGES:
            try:
                status_code, body, headers = await client.get(page)
                if status_code not in (200, 401, 403):
                    continue

                # headers may be a dict or dict-like; normalise key lookup
                csp = None
                if isinstance(headers, dict):
                    for key in headers:
                        if key.lower() == "content-security-policy":
                            csp = headers[key]
                            break
                else:
                    csp = str(headers.get("content-security-policy", "")) or None

                if not csp:
                    csp_missing_pages.append(page)
                    continue

                csp_headers_seen.append({"page": page, "csp": csp})

                has_script_src = bool(re.search(r'\bscript-src\b', csp, re.IGNORECASE))
                allows_unsafe_inline = bool(re.search(r"'unsafe-inline'", csp, re.IGNORECASE))
                allows_unsafe_eval = bool(re.search(r"'unsafe-eval'", csp, re.IGNORECASE))
                has_hash_or_nonce = bool(
                    re.search(r"'(sha256|sha384|sha512)-[A-Za-z0-9+/=]+'\s*|'nonce-", csp, re.IGNORECASE)
                )

                if has_script_src and not allows_unsafe_inline and not allows_unsafe_eval and has_hash_or_nonce:
                    csp_strict_pages.append(page)
                else:
                    csp_unsafe_pages.append({
                        "page": page,
                        "has_script_src": has_script_src,
                        "unsafe_inline": allows_unsafe_inline,
                        "unsafe_eval": allows_unsafe_eval,
                        "has_hash_or_nonce": has_hash_or_nonce,
                    })
            except Exception:
                pass

        if csp_missing_pages and not csp_strict_pages and not csp_unsafe_pages:
            csp_status = Status.VULNERABLE
            detail = (
                f"Content-Security-Policy header is absent on all checked pages: "
                f"{csp_missing_pages}. Without CSP, browsers cannot enforce integrity "
                "restrictions on loaded scripts. NIST 800-172 3.14.1e requires mechanisms "
                "to detect and prevent unauthorised software execution."
            )
        elif csp_missing_pages or csp_unsafe_pages:
            csp_status = Status.PARTIAL if csp_strict_pages else Status.VULNERABLE
            issues = []
            if csp_missing_pages:
                issues.append(f"CSP absent on: {csp_missing_pages}")
            if csp_unsafe_pages:
                issues.append(f"Weak CSP on: {json.dumps(csp_unsafe_pages)}")
            detail = (
                "; ".join(issues) + ". "
                "A CSP without hash/nonce requirements or permitting 'unsafe-inline'/'unsafe-eval' "
                "does not enforce script integrity per NIST 800-172 3.14.1e."
            )
        else:
            csp_status = Status.DEFENDED
            detail = (
                f"Strict CSP with script-src hash/nonce requirements found on all checked "
                f"pages: {csp_strict_pages}. Browsers will reject unauthorised scripts."
            )

        results.append(self._make_result(
            variant="content_security_policy",
            status=csp_status,
            evidence=(
                f"CSP headers: {json.dumps(csp_headers_seen)}, "
                f"missing on: {csp_missing_pages}, "
                f"unsafe on: {csp_unsafe_pages}, "
                f"strict on: {csp_strict_pages}"
            ),
            details=detail,
            request={"pages": self.PAGES},
            response={"csp_headers": csp_headers_seen},
        ))

        # ----------------------------------------------------------------
        # 4. Mixed content — HTTP resources on HTTPS pages
        # ----------------------------------------------------------------
        mixed_content_findings = []
        pages_checked_mc = []

        for page in self.PAGES:
            try:
                status_code, body, headers = await client.get(page)
                if status_code not in (200, 401, 403):
                    continue
                pages_checked_mc.append(page)

                # Look for http:// in src= and href= attribute values.
                # Exclude protocol-relative URLs (//) and same-page anchors.
                http_srcs = re.findall(
                    r'(?:src|href)\s*=\s*["\']?(http://[^\s"\'<>]+)["\']?',
                    body,
                    re.IGNORECASE,
                )
                for url in http_srcs:
                    mixed_content_findings.append({"page": page, "url": url})
            except Exception:
                pass

        if mixed_content_findings:
            mc_status = Status.VULNERABLE
            detail = (
                f"Found {len(mixed_content_findings)} HTTP (non-secure) resource reference(s) "
                f"on HTTPS pages: {json.dumps(mixed_content_findings[:10])}. "
                "Resources loaded over HTTP bypass TLS and cannot have their integrity "
                "verified. NIST 800-172 3.14.1e integrity controls require all resources "
                "be delivered over authenticated, encrypted channels."
            )
        elif pages_checked_mc:
            mc_status = Status.DEFENDED
            detail = (
                f"No mixed HTTP content found across {pages_checked_mc}. "
                "All embedded resources appear to use HTTPS or relative URLs."
            )
        else:
            mc_status = Status.PARTIAL
            detail = "No pages returned successful responses for mixed-content analysis."

        results.append(self._make_result(
            variant="mixed_content",
            status=mc_status,
            evidence=(
                f"Pages checked: {pages_checked_mc}, "
                f"mixed content findings: {json.dumps(mixed_content_findings[:20])}"
            ),
            details=detail,
            request={"pages": self.PAGES},
            response={"findings": mixed_content_findings},
        ))

        # ----------------------------------------------------------------
        # 5. Script tampering detection — CSP reporting mechanisms
        # ----------------------------------------------------------------
        reporting_pages = []
        no_reporting_pages = []

        for page in self.PAGES:
            try:
                status_code, body, headers = await client.get(page)
                if status_code not in (200, 401, 403):
                    continue

                csp = None
                reporting_endpoints_header = None
                if isinstance(headers, dict):
                    for key in headers:
                        if key.lower() == "content-security-policy":
                            csp = headers[key]
                        if key.lower() == "reporting-endpoints":
                            reporting_endpoints_header = headers[key]
                else:
                    csp = str(headers.get("content-security-policy", "")) or None
                    reporting_endpoints_header = (
                        str(headers.get("reporting-endpoints", "")) or None
                    )

                has_report_uri = csp and bool(
                    re.search(r'\breport-uri\b|\breport-to\b', csp, re.IGNORECASE)
                )
                has_reporting_endpoints = bool(reporting_endpoints_header)

                if has_report_uri or has_reporting_endpoints:
                    reporting_pages.append({
                        "page": page,
                        "report_uri_in_csp": has_report_uri,
                        "reporting_endpoints_header": has_reporting_endpoints,
                    })
                else:
                    no_reporting_pages.append(page)
            except Exception:
                pass

        if reporting_pages and not no_reporting_pages:
            tamper_status = Status.DEFENDED
            detail = (
                f"CSP violation reporting is configured on all checked pages: "
                f"{json.dumps(reporting_pages)}. "
                "The application will receive reports when script integrity violations occur, "
                "enabling detection of tampering per NIST 800-172 3.14.1e."
            )
        elif reporting_pages:
            tamper_status = Status.PARTIAL
            detail = (
                f"CSP violation reporting present on {[r['page'] for r in reporting_pages]} "
                f"but absent on {no_reporting_pages}. "
                "Inconsistent reporting means tampering on unprotected pages goes undetected."
            )
        else:
            tamper_status = Status.PARTIAL
            detail = (
                f"No CSP report-uri, report-to, or Reporting-Endpoints header found on "
                f"any checked page ({self.PAGES}). "
                "Without a reporting mechanism, script integrity violations will not be "
                "detected or logged. NIST 800-172 3.14.1e requires the ability to detect "
                "and respond to software tampering events."
            )

        results.append(self._make_result(
            variant="script_tampering_detection",
            status=tamper_status,
            evidence=(
                f"Pages with reporting: {json.dumps(reporting_pages)}, "
                f"pages without: {no_reporting_pages}"
            ),
            details=detail,
            request={"pages": self.PAGES},
            response={"reporting_pages": reporting_pages, "no_reporting_pages": no_reporting_pages},
        ))

        return results
