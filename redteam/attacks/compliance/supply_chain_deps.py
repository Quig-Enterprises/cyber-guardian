"""Supply chain dependency risk assessment — NIST SP 800-172 Control 3.11.6e.

Audits application dependencies for known CVEs, dependency confusion
vulnerabilities, and verifies package integrity by checking publicly
accessible manifests, version disclosures, outdated JS libraries,
subresource integrity, and CDN dependency confusion vectors.
"""

import json
import re

from redteam.base import Attack, AttackResult, Severity, Status


class SupplyChainDepsAttack(Attack):
    name = "compliance.supply_chain_deps"
    category = "compliance"
    severity = Severity.HIGH
    description = (
        "NIST 800-172 3.11.6e — Assess supply chain risks in application dependencies"
    )

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # ----------------------------------------------------------------
        # 1. exposed_dependency_files
        # Check if dependency manifests are publicly accessible via web.
        # ----------------------------------------------------------------
        dep_files = [
            "/composer.json",
            "/composer.lock",
            "/package.json",
            "/package-lock.json",
            "/requirements.txt",
            "/Pipfile.lock",
            "/.npmrc",
        ]

        exposed = []
        for path in dep_files:
            status_code, body, headers = await client.get(path)
            if status_code == 200:
                exposed.append(path)

        if exposed:
            dep_status = Status.VULNERABLE
            detail = (
                f"Dependency manifest(s) publicly accessible: {', '.join(exposed)}. "
                "Attackers can enumerate exact dependency versions to identify known CVEs "
                "and craft targeted supply chain attacks. NIST 800-172 3.11.6e requires "
                "supply chain risk management controls."
            )
            evidence = f"Exposed files ({len(exposed)}): {', '.join(exposed)}"
        else:
            dep_status = Status.DEFENDED
            detail = (
                "No dependency manifest files were accessible at common web paths. "
                "Supply chain reconnaissance via file exposure is mitigated."
            )
            evidence = f"Checked {len(dep_files)} paths, all returned non-200 status."

        results.append(self._make_result(
            variant="exposed_dependency_files",
            status=dep_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
            request={"paths_checked": dep_files},
            response={"exposed": exposed},
        ))

        # ----------------------------------------------------------------
        # 2. server_version_disclosure
        # Check response headers and error pages for framework/library
        # version info that reveals dependency versions.
        # ----------------------------------------------------------------
        status_code, body, headers = await client.get("/")
        headers_str = json.dumps(dict(headers)) if isinstance(headers, dict) else str(headers)

        version_patterns = [
            (r"PHP/(\d+\.\d+[\.\d]*)", "PHP"),
            (r"Apache/(\d+\.\d+[\.\d]*)", "Apache"),
            (r"nginx/(\d+\.\d+[\.\d]*)", "nginx"),
            (r"Express/(\d+\.\d+[\.\d]*)", "Express"),
            (r"Laravel/(\d+\.\d+[\.\d]*)", "Laravel"),
            (r"Symfony/(\d+\.\d+[\.\d]*)", "Symfony"),
            (r"Django/(\d+\.\d+[\.\d]*)", "Django"),
            (r"Rails/(\d+\.\d+[\.\d]*)", "Rails"),
        ]

        disclosed_versions = []
        for pattern, framework in version_patterns:
            match = re.search(pattern, headers_str, re.IGNORECASE)
            if match:
                disclosed_versions.append(f"{framework} {match.group(1)}")
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version_str = f"{framework} {match.group(1)}"
                if version_str not in disclosed_versions:
                    disclosed_versions.append(version_str)

        # Also check specific headers
        server_header = ""
        powered_by = ""
        if isinstance(headers, dict):
            server_header = headers.get("Server", headers.get("server", ""))
            powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))

        has_detailed_version = bool(
            re.search(r"\d+\.\d+", server_header) or
            re.search(r"\d+\.\d+", powered_by) or
            disclosed_versions
        )

        if has_detailed_version:
            ver_status = Status.PARTIAL
            detail = (
                f"Detailed version information exposed in headers/responses: "
                f"{', '.join(disclosed_versions) or 'see evidence'}. "
                "Attackers can cross-reference disclosed versions against CVE databases "
                "to identify exploitable vulnerabilities in dependencies."
            )
            evidence = (
                f"Server: {server_header!r}, X-Powered-By: {powered_by!r}, "
                f"Detected versions: {disclosed_versions}"
            )
        else:
            ver_status = Status.DEFENDED
            detail = (
                "No detailed framework or dependency version information found in "
                "response headers or error pages."
            )
            evidence = f"Server: {server_header!r}, X-Powered-By: {powered_by!r}"

        results.append(self._make_result(
            variant="server_version_disclosure",
            status=ver_status,
            severity=Severity.MEDIUM,
            evidence=evidence,
            details=detail,
            request={"endpoint": "/", "checked": ["Server", "X-Powered-By", "body"]},
            response={"status": status_code, "server": server_header, "powered_by": powered_by},
        ))

        # ----------------------------------------------------------------
        # 3. outdated_javascript_libraries
        # Fetch main HTML pages and look for known vulnerable JS library
        # patterns in <script> tags.
        # ----------------------------------------------------------------
        pages_to_check = ["/", "/index.php", "/admin/login.php"]
        outdated_libs = []

        # Patterns: (regex for version in src URL, library name, vulnerable_check_fn)
        lib_patterns = [
            # jQuery < 3.5.0 — XSS via html() before 3.5.0
            (r'jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', "jQuery", lambda v: _version_lt(v, (3, 5, 0))),
            # Bootstrap < 4.3.1 — XSS vulnerability
            (r'bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)', "Bootstrap", lambda v: _version_lt(v, (4, 3, 1))),
            # Angular < 1.8.0 — multiple CVEs in older 1.x
            (r'angular(?:js)?[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', "AngularJS", lambda v: _version_lt(v, (1, 8, 0))),
            # Lodash < 4.17.21 — prototype pollution
            (r'lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', "Lodash", lambda v: _version_lt(v, (4, 17, 21))),
            # Moment.js — any version (deprecated, ReDoS CVEs)
            (r'moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', "Moment.js", lambda v: True),
        ]

        all_scripts = []
        for page in pages_to_check:
            status_code, body, headers = await client.get(page)
            if status_code == 200:
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
                all_scripts.extend(scripts)

        for src in all_scripts:
            for pattern, lib_name, is_vulnerable in lib_patterns:
                match = re.search(pattern, src, re.IGNORECASE)
                if match:
                    version_str = match.group(1)
                    try:
                        parts = tuple(int(x) for x in version_str.split(".")[:3])
                        if is_vulnerable(parts):
                            entry = f"{lib_name} {version_str} ({src})"
                            if entry not in outdated_libs:
                                outdated_libs.append(entry)
                    except (ValueError, TypeError):
                        pass

        if outdated_libs:
            js_status = Status.VULNERABLE
            detail = (
                f"Outdated/vulnerable JavaScript libraries detected: {', '.join(outdated_libs)}. "
                "These library versions have known CVEs that can be exploited for XSS, "
                "prototype pollution, or ReDoS attacks. Update to current versions immediately."
            )
            evidence = f"Vulnerable libraries found: {outdated_libs}"
        else:
            js_status = Status.DEFENDED
            detail = (
                "No outdated JavaScript libraries with known CVEs detected in "
                "script tags across checked pages."
            )
            evidence = f"Checked {len(all_scripts)} script sources across {len(pages_to_check)} pages."

        results.append(self._make_result(
            variant="outdated_javascript_libraries",
            status=js_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
            request={"pages_checked": pages_to_check},
            response={"scripts_found": len(all_scripts), "outdated": outdated_libs},
        ))

        # ----------------------------------------------------------------
        # 4. subresource_integrity_missing
        # Check if external <script> and <link> tags have integrity
        # attributes (SRI).
        # ----------------------------------------------------------------
        sri_pages = ["/admin/login.php", "/", "/index.php"]
        external_without_sri = []
        external_with_sri = []

        # Detect external resources (different origin or absolute URL to CDN)
        external_pattern = re.compile(
            r'(https?://(?!(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)))',
            re.IGNORECASE
        )

        for page in sri_pages:
            status_code, body, headers = await client.get(page)
            if status_code != 200:
                continue

            # External scripts
            for match in re.finditer(
                r'<script([^>]+)>', body, re.IGNORECASE | re.DOTALL
            ):
                tag = match.group(1)
                if re.search(r'src=["\']https?://', tag, re.IGNORECASE):
                    src = re.search(r'src=["\']([^"\']+)["\']', tag)
                    src_val = src.group(1) if src else tag[:80]
                    if "integrity=" in tag.lower():
                        external_with_sri.append(f"script:{src_val}")
                    else:
                        external_without_sri.append(f"script:{src_val}")

            # External stylesheets
            for match in re.finditer(
                r'<link([^>]+)>', body, re.IGNORECASE | re.DOTALL
            ):
                tag = match.group(1)
                if re.search(r'href=["\']https?://', tag, re.IGNORECASE):
                    href = re.search(r'href=["\']([^"\']+)["\']', tag)
                    href_val = href.group(1) if href else tag[:80]
                    if "integrity=" in tag.lower():
                        external_with_sri.append(f"link:{href_val}")
                    else:
                        external_without_sri.append(f"link:{href_val}")

        if external_without_sri:
            sri_status = Status.VULNERABLE
            detail = (
                f"{len(external_without_sri)} external resource(s) loaded without "
                f"Subresource Integrity (SRI) attributes: {external_without_sri[:5]}. "
                "An attacker who compromises a CDN or performs a MITM attack can inject "
                "malicious code. Add integrity and crossorigin attributes to all external "
                "resources per NIST 800-172 supply chain integrity requirements."
            )
            evidence = (
                f"External resources without SRI: {external_without_sri[:5]}, "
                f"with SRI: {len(external_with_sri)}"
            )
        elif external_with_sri:
            sri_status = Status.DEFENDED
            detail = (
                f"All {len(external_with_sri)} detected external resources have SRI integrity "
                "attributes. Supply chain injection via CDN compromise is mitigated."
            )
            evidence = f"SRI-protected resources: {len(external_with_sri)}"
        else:
            sri_status = Status.DEFENDED
            detail = "No external resources detected in checked pages."
            evidence = f"Pages checked: {sri_pages}"

        results.append(self._make_result(
            variant="subresource_integrity_missing",
            status=sri_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
            request={"pages_checked": sri_pages},
            response={
                "external_without_sri": len(external_without_sri),
                "external_with_sri": len(external_with_sri),
                "samples": external_without_sri[:3],
            },
        ))

        # ----------------------------------------------------------------
        # 5. dependency_confusion_probing
        # Check if the application loads resources from public CDNs or
        # package registries that could be targeted by dependency confusion.
        # ----------------------------------------------------------------
        cdn_patterns = {
            "npm (unpkg)": r'unpkg\.com',
            "npm (jsdelivr)": r'cdn\.jsdelivr\.net/npm',
            "cdnjs": r'cdnjs\.cloudflare\.com',
            "jsdelivr (gh)": r'cdn\.jsdelivr\.net/gh',
            "rawgit": r'rawgit\.com|raw\.githack\.com',
            "skypack": r'cdn\.skypack\.dev',
        }

        cdn_refs = {}
        cdn_pages = ["/", "/index.php", "/admin/login.php"]

        for page in cdn_pages:
            status_code, body, headers = await client.get(page)
            if status_code != 200:
                continue
            for cdn_name, pattern in cdn_patterns.items():
                matches = re.findall(
                    rf'(?:src|href)=["\']([^"\']*{pattern}[^"\']*)["\']',
                    body,
                    re.IGNORECASE,
                )
                if matches:
                    if cdn_name not in cdn_refs:
                        cdn_refs[cdn_name] = []
                    cdn_refs[cdn_name].extend(matches)

        # Check if those CDN resources lack SRI (already checked above but
        # here we focus on the confusion angle — public registry loading)
        cdn_without_sri = []
        for page in cdn_pages:
            status_code, body, headers = await client.get(page)
            if status_code != 200:
                continue
            for cdn_name, pattern in cdn_patterns.items():
                for tag_match in re.finditer(
                    rf'<(?:script|link)([^>]*{pattern}[^>]*)>', body, re.IGNORECASE | re.DOTALL
                ):
                    tag = tag_match.group(1)
                    if "integrity=" not in tag.lower():
                        url_match = re.search(r'(?:src|href)=["\']([^"\']+)["\']', tag)
                        if url_match:
                            cdn_without_sri.append(f"{cdn_name}: {url_match.group(1)}")

        if cdn_refs and cdn_without_sri:
            confusion_status = Status.PARTIAL
            detail = (
                f"Application loads resources from public CDN/package registries "
                f"({', '.join(cdn_refs.keys())}) without Subresource Integrity checks. "
                "Dependency confusion attacks can substitute internal package names with "
                "malicious public packages. Ensure all CDN resources have SRI hashes and "
                "consider hosting critical dependencies internally per NIST 800-172 3.11.6e."
            )
            evidence = (
                f"CDNs in use: {list(cdn_refs.keys())}, "
                f"unprotected CDN resources: {cdn_without_sri[:5]}"
            )
        elif cdn_refs:
            confusion_status = Status.PARTIAL
            detail = (
                f"Application uses public CDNs ({', '.join(cdn_refs.keys())}). "
                "While SRI may be present, reliance on public CDNs introduces supply chain "
                "risk. Consider self-hosting critical dependencies."
            )
            evidence = f"CDNs detected: {list(cdn_refs.keys())}"
        else:
            confusion_status = Status.DEFENDED
            detail = (
                "No references to public CDN/package registries detected. "
                "Dependency confusion via CDN appears to be mitigated."
            )
            evidence = f"CDN patterns checked across {len(cdn_pages)} pages, none found."

        results.append(self._make_result(
            variant="dependency_confusion_probing",
            status=confusion_status,
            severity=Severity.MEDIUM,
            evidence=evidence,
            details=detail,
            request={"pages_checked": cdn_pages, "cdn_patterns": list(cdn_patterns.keys())},
            response={"cdns_found": list(cdn_refs.keys()), "unprotected_count": len(cdn_without_sri)},
        ))

        return results


def _version_lt(version_tuple: tuple, threshold: tuple) -> bool:
    """Return True if version_tuple is strictly less than threshold."""
    return version_tuple < threshold
