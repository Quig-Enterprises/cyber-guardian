"""WordPress information disclosure attacks — MEDIUM severity.

Tests for common WordPress information disclosure vectors including
version exposure via readme.html, generator meta tags, RSS feeds,
static asset version parameters, and directory listing on uploads/themes.
"""

import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

VERSION_README_RE = re.compile(r"Version\s+([\d.]+)", re.IGNORECASE)
GENERATOR_META_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']',
    re.IGNORECASE,
)
FEED_GENERATOR_RE = re.compile(
    r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>",
    re.IGNORECASE,
)
PHP_VERSION_RE = re.compile(r"PHP/([\d.]+)", re.IGNORECASE)


class InfoDisclosureAttack(Attack):
    """Test for WordPress information disclosure paths."""

    name = "wordpress.info_disclosure"
    category = "wordpress"
    severity = Severity.MEDIUM
    description = "WordPress information disclosure via version leaks, directory listing, and headers"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results = []

        results.append(await self._test_readme_html(client))
        results.append(await self._test_license_txt(client))
        results.append(await self._test_generator_meta(client))
        results.append(await self._test_feed_generator(client))
        results.append(await self._test_wp_includes_version(client))
        results.append(await self._test_directory_listing_uploads(client))
        results.append(await self._test_directory_listing_themes(client))
        results.append(await self._test_php_version_header(client))

        return results

    # ------------------------------------------------------------------
    # readme.html
    # ------------------------------------------------------------------
    async def _test_readme_html(self, client) -> AttackResult:
        """GET /readme.html — reveals WordPress version."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/readme.html", cookies={})
            duration = (time.monotonic() - start) * 1000

            if status == 200 and "wordpress" in body.lower():
                match = VERSION_README_RE.search(body)
                version = match.group(1) if match else "unknown"
                return self._make_result(
                    variant="readme_html",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"readme.html accessible, WordPress version: {version}",
                    details=(
                        f"/readme.html returned HTTP {status} confirming WordPress. "
                        f"Detected version: {version}. "
                        f"This file should be removed or access-restricted in production."
                    ),
                    request={"method": "GET", "path": "/readme.html"},
                    response={"status": status, "body": body[:400]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="readme_html",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, readme.html not exposed",
                details=f"/readme.html returned HTTP {status} with no WordPress content.",
                request={"method": "GET", "path": "/readme.html"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="readme_html",
                status=Status.ERROR,
                details=f"Error testing readme.html: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # license.txt
    # ------------------------------------------------------------------
    async def _test_license_txt(self, client) -> AttackResult:
        """GET /license.txt — confirms WordPress installation."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/license.txt", cookies={})
            duration = (time.monotonic() - start) * 1000

            wp_indicators = ["wordpress", "gnu general public license", "gpl"]
            found = [ind for ind in wp_indicators if ind in body.lower()]

            if status == 200 and found:
                return self._make_result(
                    variant="license_txt",
                    status=Status.VULNERABLE,
                    severity=Severity.INFO,
                    evidence=f"license.txt accessible, confirms WordPress ({', '.join(found)})",
                    details=(
                        f"/license.txt returned HTTP {status} with WordPress-related "
                        f"content. Indicators: {', '.join(found)}. "
                        f"Confirms WordPress installation to attackers."
                    ),
                    request={"method": "GET", "path": "/license.txt"},
                    response={"status": status, "body": body[:300]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="license_txt",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, license.txt not exposed",
                details=f"/license.txt returned HTTP {status} with no WordPress indicators.",
                request={"method": "GET", "path": "/license.txt"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="license_txt",
                status=Status.ERROR,
                details=f"Error testing license.txt: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # Generator meta tag
    # ------------------------------------------------------------------
    async def _test_generator_meta(self, client) -> AttackResult:
        """GET / — check for <meta name="generator"> version disclosure."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            match = GENERATOR_META_RE.search(body)
            if match:
                version = match.group(1)
                return self._make_result(
                    variant="generator_meta",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"Generator meta tag exposes WordPress {version}",
                    details=(
                        f"Homepage contains <meta name=\"generator\" content=\"WordPress {version}\">. "
                        f"This discloses the exact WordPress version to any visitor. "
                        f"Use remove_action('wp_head', 'wp_generator') to remove."
                    ),
                    request={"method": "GET", "path": "/"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="generator_meta",
                status=Status.DEFENDED,
                evidence="No generator meta tag found on homepage",
                details="Homepage does not contain a WordPress generator meta tag.",
                request={"method": "GET", "path": "/"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="generator_meta",
                status=Status.ERROR,
                details=f"Error testing generator meta: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # RSS feed generator tag
    # ------------------------------------------------------------------
    async def _test_feed_generator(self, client) -> AttackResult:
        """GET /feed/ — check for <generator> version in RSS feed."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/feed/", cookies={})
            duration = (time.monotonic() - start) * 1000

            match = FEED_GENERATOR_RE.search(body)
            if match:
                version = match.group(1)
                return self._make_result(
                    variant="feed_generator",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"RSS feed generator tag exposes WordPress {version}",
                    details=(
                        f"/feed/ contains <generator> tag with WordPress version {version}. "
                        f"RSS feeds often retain version information even when removed from HTML head."
                    ),
                    request={"method": "GET", "path": "/feed/"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="feed_generator",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no version in feed generator tag",
                details="RSS feed does not expose WordPress version in generator tag.",
                request={"method": "GET", "path": "/feed/"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="feed_generator",
                status=Status.ERROR,
                details=f"Error testing feed generator: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # wp-includes JS version
    # ------------------------------------------------------------------
    async def _test_wp_includes_version(self, client) -> AttackResult:
        """GET /wp-includes/js/jquery/jquery.min.js — confirms WP presence."""
        path = "/wp-includes/js/jquery/jquery.min.js"
        start = time.monotonic()
        try:
            status, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000

            if status == 200 and len(body) > 100:
                return self._make_result(
                    variant="wp_includes_version",
                    status=Status.VULNERABLE,
                    severity=Severity.INFO,
                    evidence=f"wp-includes jQuery accessible (HTTP {status}, {len(body)} bytes)",
                    details=(
                        f"Static asset at {path} is accessible (HTTP {status}). "
                        f"Confirms WordPress installation and allows fingerprinting "
                        f"via bundled library versions."
                    ),
                    request={"method": "GET", "path": path},
                    response={"status": status, "body_length": len(body)},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="wp_includes_version",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, wp-includes asset not accessible",
                details=f"Static asset {path} returned HTTP {status}.",
                request={"method": "GET", "path": path},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="wp_includes_version",
                status=Status.ERROR,
                details=f"Error testing wp-includes version: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # Directory listing — uploads
    # ------------------------------------------------------------------
    async def _test_directory_listing_uploads(self, client) -> AttackResult:
        """GET /wp-content/uploads/ — check for directory listing."""
        path = f"{client.content_path}/uploads/"
        start = time.monotonic()
        try:
            status, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000

            if status == 200 and "Index of" in body:
                return self._make_result(
                    variant="directory_listing_uploads",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence="Directory listing enabled on wp-content/uploads/",
                    details=(
                        f"GET {path} returned directory listing (HTTP {status}). "
                        f"All uploaded media files are browsable. Attackers can discover "
                        f"sensitive documents, images, and backup files."
                    ),
                    request={"method": "GET", "path": path},
                    response={"status": status, "body": body[:400]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="directory_listing_uploads",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no directory listing on uploads",
                details=f"Uploads directory does not expose directory listing.",
                request={"method": "GET", "path": path},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="directory_listing_uploads",
                status=Status.ERROR,
                details=f"Error testing uploads directory listing: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # Directory listing — themes
    # ------------------------------------------------------------------
    async def _test_directory_listing_themes(self, client) -> AttackResult:
        """GET /wp-content/themes/ — check for directory listing."""
        path = f"{client.content_path}/themes/"
        start = time.monotonic()
        try:
            status, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000

            if status == 200 and "Index of" in body:
                return self._make_result(
                    variant="directory_listing_themes",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence="Directory listing enabled on wp-content/themes/",
                    details=(
                        f"GET {path} returned directory listing (HTTP {status}). "
                        f"Installed themes are enumerable, aiding targeted attacks "
                        f"against known theme vulnerabilities."
                    ),
                    request={"method": "GET", "path": path},
                    response={"status": status, "body": body[:400]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="directory_listing_themes",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no directory listing on themes",
                details=f"Themes directory does not expose directory listing.",
                request={"method": "GET", "path": path},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="directory_listing_themes",
                status=Status.ERROR,
                details=f"Error testing themes directory listing: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # PHP version header
    # ------------------------------------------------------------------
    async def _test_php_version_header(self, client) -> AttackResult:
        """Check response headers for X-Powered-By PHP version disclosure."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            powered_by = headers.get("X-Powered-By", "")
            match = PHP_VERSION_RE.search(powered_by)

            if match:
                php_version = match.group(1)
                return self._make_result(
                    variant="php_version_header",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"X-Powered-By header exposes PHP {php_version}",
                    details=(
                        f"Response header X-Powered-By: {powered_by}. "
                        f"PHP version {php_version} is disclosed. "
                        f"Set expose_php = Off in php.ini to suppress this header."
                    ),
                    request={"method": "GET", "path": "/"},
                    response={"status": status, "headers": {"X-Powered-By": powered_by}},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="php_version_header",
                status=Status.DEFENDED,
                evidence="No X-Powered-By header with PHP version found",
                details="Response headers do not expose PHP version information.",
                request={"method": "GET", "path": "/"},
                response={"status": status, "headers": dict(headers)},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="php_version_header",
                status=Status.ERROR,
                details=f"Error testing PHP version header: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
