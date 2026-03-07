"""Subresource Integrity (SRI) checks for external scripts and stylesheets.

Fetches the target homepage and inspects all <script> and <link> tags that
load resources from external domains.  Any external resource missing an
``integrity`` attribute is flagged because a compromised CDN could inject
malicious code.

Evaluation:
- External script without integrity attribute -> VULNERABLE
- External stylesheet without integrity attribute -> VULNERABLE
- Known CDN resource without SRI -> VULNERABLE (higher confidence)
- All external resources have SRI -> DEFENDED
"""

import re
import time
import logging
from urllib.parse import urlparse

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Known CDN domains where SRI is especially important
KNOWN_CDNS = {
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "stackpath.bootstrapcdn.com",
    "cdn.bootcdn.net",
    "code.jquery.com",
    "maxcdn.bootstrapcdn.com",
    "cdn.datatables.net",
    "cdn.tailwindcss.com",
}

# Regex to find <script> tags with src attribute
SCRIPT_RE = re.compile(
    r'<script\b([^>]*)>',
    re.IGNORECASE | re.DOTALL,
)

# Regex to find <link> tags with rel="stylesheet"
LINK_RE = re.compile(
    r'<link\b([^>]*)>',
    re.IGNORECASE | re.DOTALL,
)

# Attribute extractors
SRC_RE = re.compile(r'''src\s*=\s*["']([^"']+)["']''', re.IGNORECASE)
HREF_RE = re.compile(r'''href\s*=\s*["']([^"']+)["']''', re.IGNORECASE)
INTEGRITY_RE = re.compile(r'''integrity\s*=\s*["']([^"']+)["']''', re.IGNORECASE)
REL_RE = re.compile(r'''rel\s*=\s*["']([^"']+)["']''', re.IGNORECASE)


class SRIAttack(Attack):
    """Subresource Integrity checks for external resources."""

    name = "web.sri"
    category = "web"
    severity = Severity.MEDIUM
    description = "Subresource Integrity (SRI) checks for external scripts and stylesheets"
    target_types = {"app", "wordpress", "generic"}

    def _get_target_domain(self) -> str:
        """Return the target domain from config."""
        base_url = self._config.get("target", {}).get("base_url", "")
        parsed = urlparse(base_url)
        return parsed.hostname or ""

    def _is_external(self, url: str, target_domain: str) -> bool:
        """Determine whether a URL points to an external domain."""
        if url.startswith("//"):
            url = "https:" + url
        parsed = urlparse(url)
        if not parsed.hostname:
            return False
        return parsed.hostname.lower() != target_domain.lower()

    def _is_cdn(self, url: str) -> bool:
        """Check if the URL is from a known CDN."""
        if url.startswith("//"):
            url = "https:" + url
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        return any(hostname == cdn or hostname.endswith("." + cdn) for cdn in KNOWN_CDNS)

    async def execute(self, client) -> list[AttackResult]:
        """Run all SRI variants."""
        results = []

        # Fetch homepage HTML
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get("/", cookies={})
        except Exception as e:
            for variant in ("external_scripts", "external_styles", "cdn_resources"):
                results.append(self._make_result(
                    variant=variant,
                    status=Status.ERROR,
                    details=f"Failed to fetch homepage: {e}",
                ))
            return results

        fetch_duration = (time.monotonic() - start) * 1000
        target_domain = self._get_target_domain()

        if status_code != 200:
            for variant in ("external_scripts", "external_styles", "cdn_resources"):
                results.append(self._make_result(
                    variant=variant,
                    status=Status.ERROR,
                    details=f"Homepage returned HTTP {status_code}",
                    response={"status": status_code},
                ))
            return results

        # -- Variant: external_scripts --
        results.append(self._check_external_scripts(body, target_domain, fetch_duration))

        # -- Variant: external_styles --
        results.append(self._check_external_styles(body, target_domain, fetch_duration))

        # -- Variant: cdn_resources --
        results.append(self._check_cdn_resources(body, target_domain, fetch_duration))

        return results

    def _check_external_scripts(self, html: str, target_domain: str,
                                base_duration: float) -> AttackResult:
        """external_scripts: Flag external <script> tags without integrity."""
        start = time.monotonic()

        missing_sri = []
        total_external = 0

        for match in SCRIPT_RE.finditer(html):
            attrs = match.group(1)
            src_match = SRC_RE.search(attrs)
            if not src_match:
                continue
            src = src_match.group(1)
            if not self._is_external(src, target_domain):
                continue

            total_external += 1
            has_integrity = bool(INTEGRITY_RE.search(attrs))
            if not has_integrity:
                missing_sri.append(src)

        duration = base_duration + (time.monotonic() - start) * 1000

        if missing_sri:
            return self._make_result(
                variant="external_scripts",
                status=Status.VULNERABLE,
                evidence=f"{len(missing_sri)}/{total_external} external scripts lack SRI",
                details=(
                    f"External scripts without integrity attribute: "
                    f"{', '.join(missing_sri[:5])}"
                    f"{f' (+{len(missing_sri)-5} more)' if len(missing_sri) > 5 else ''}"
                ),
                request={"checked": "/"},
                response={"total_external_scripts": total_external,
                          "missing_sri": missing_sri[:10]},
                duration_ms=duration,
            )
        elif total_external > 0:
            return self._make_result(
                variant="external_scripts",
                status=Status.DEFENDED,
                evidence=f"All {total_external} external scripts have SRI",
                details="Every external script tag includes an integrity attribute",
                request={"checked": "/"},
                response={"total_external_scripts": total_external},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="external_scripts",
                status=Status.DEFENDED,
                evidence="No external scripts found",
                details="Page does not load any scripts from external domains",
                request={"checked": "/"},
                response={"total_external_scripts": 0},
                duration_ms=duration,
            )

    def _check_external_styles(self, html: str, target_domain: str,
                               base_duration: float) -> AttackResult:
        """external_styles: Flag external stylesheets without integrity."""
        start = time.monotonic()

        missing_sri = []
        total_external = 0

        for match in LINK_RE.finditer(html):
            attrs = match.group(1)
            # Only consider stylesheet links
            rel_match = REL_RE.search(attrs)
            if not rel_match or "stylesheet" not in rel_match.group(1).lower():
                continue
            href_match = HREF_RE.search(attrs)
            if not href_match:
                continue
            href = href_match.group(1)
            if not self._is_external(href, target_domain):
                continue

            total_external += 1
            has_integrity = bool(INTEGRITY_RE.search(attrs))
            if not has_integrity:
                missing_sri.append(href)

        duration = base_duration + (time.monotonic() - start) * 1000

        if missing_sri:
            return self._make_result(
                variant="external_styles",
                status=Status.VULNERABLE,
                evidence=f"{len(missing_sri)}/{total_external} external stylesheets lack SRI",
                details=(
                    f"External stylesheets without integrity attribute: "
                    f"{', '.join(missing_sri[:5])}"
                    f"{f' (+{len(missing_sri)-5} more)' if len(missing_sri) > 5 else ''}"
                ),
                request={"checked": "/"},
                response={"total_external_styles": total_external,
                          "missing_sri": missing_sri[:10]},
                duration_ms=duration,
            )
        elif total_external > 0:
            return self._make_result(
                variant="external_styles",
                status=Status.DEFENDED,
                evidence=f"All {total_external} external stylesheets have SRI",
                details="Every external stylesheet link includes an integrity attribute",
                request={"checked": "/"},
                response={"total_external_styles": total_external},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="external_styles",
                status=Status.DEFENDED,
                evidence="No external stylesheets found",
                details="Page does not load any stylesheets from external domains",
                request={"checked": "/"},
                response={"total_external_styles": 0},
                duration_ms=duration,
            )

    def _check_cdn_resources(self, html: str, target_domain: str,
                             base_duration: float) -> AttackResult:
        """cdn_resources: Specifically check known CDN resources for SRI."""
        start = time.monotonic()

        cdn_missing_sri = []
        total_cdn = 0

        # Check scripts
        for match in SCRIPT_RE.finditer(html):
            attrs = match.group(1)
            src_match = SRC_RE.search(attrs)
            if not src_match:
                continue
            src = src_match.group(1)
            if not self._is_cdn(src):
                continue
            total_cdn += 1
            if not INTEGRITY_RE.search(attrs):
                cdn_missing_sri.append(("script", src))

        # Check stylesheets
        for match in LINK_RE.finditer(html):
            attrs = match.group(1)
            rel_match = REL_RE.search(attrs)
            if not rel_match or "stylesheet" not in rel_match.group(1).lower():
                continue
            href_match = HREF_RE.search(attrs)
            if not href_match:
                continue
            href = href_match.group(1)
            if not self._is_cdn(href):
                continue
            total_cdn += 1
            if not INTEGRITY_RE.search(attrs):
                cdn_missing_sri.append(("stylesheet", href))

        duration = base_duration + (time.monotonic() - start) * 1000

        if cdn_missing_sri:
            return self._make_result(
                variant="cdn_resources",
                status=Status.VULNERABLE,
                evidence=f"{len(cdn_missing_sri)}/{total_cdn} CDN resources lack SRI",
                details=(
                    f"CDN resources without integrity attribute are high-risk supply chain targets. "
                    f"Missing SRI: {', '.join(r[1] for r in cdn_missing_sri[:5])}"
                    f"{f' (+{len(cdn_missing_sri)-5} more)' if len(cdn_missing_sri) > 5 else ''}"
                ),
                request={"checked": "/", "known_cdns": sorted(KNOWN_CDNS)[:5]},
                response={"total_cdn_resources": total_cdn,
                          "missing_sri": [{"type": t, "url": u} for t, u in cdn_missing_sri[:10]]},
                duration_ms=duration,
            )
        elif total_cdn > 0:
            return self._make_result(
                variant="cdn_resources",
                status=Status.DEFENDED,
                evidence=f"All {total_cdn} CDN resources have SRI",
                details="Every resource loaded from known CDNs includes an integrity attribute",
                request={"checked": "/"},
                response={"total_cdn_resources": total_cdn},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="cdn_resources",
                status=Status.DEFENDED,
                evidence="No resources from known CDNs detected",
                details="Page does not load resources from common CDN domains",
                request={"checked": "/"},
                response={"total_cdn_resources": 0},
                duration_ms=duration,
            )
