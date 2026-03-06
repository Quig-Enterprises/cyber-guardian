"""WordPress cron system abuse attacks — MEDIUM severity.

Tests the WordPress cron system (wp-cron.php) for external accessibility,
denial-of-service potential via rapid triggering, cron event enumeration,
and alternate cron detection.

Skipped entirely in AWS mode to avoid triggering DoS protections.
"""

import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

DOING_CRON_RE = re.compile(r"doing_wp_cron[=&]", re.IGNORECASE)


class CronAbuseAttack(Attack):
    """Test WordPress cron system for abuse potential."""

    name = "wordpress.cron_abuse"
    category = "wordpress"
    severity = Severity.MEDIUM
    description = "WordPress cron system accessibility and denial-of-service potential"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        # Skip entirely in AWS mode
        if self._is_aws_mode():
            return [self._make_result(
                variant="aws_skip",
                status=Status.SKIPPED,
                severity=Severity.INFO,
                evidence="Skipped in AWS mode",
                details=(
                    "WordPress cron abuse tests are skipped in AWS mode to avoid "
                    "triggering DoS protections and rate-limiting infrastructure."
                ),
            )]

        results = []

        results.append(await self._test_wp_cron_accessible(client))
        results.append(await self._test_wp_cron_dos(client))
        results.append(await self._test_cron_event_enumeration(client))
        results.append(await self._test_alternate_cron(client))

        return results

    # ------------------------------------------------------------------
    # wp-cron.php accessibility
    # ------------------------------------------------------------------
    async def _test_wp_cron_accessible(self, client) -> AttackResult:
        """GET /wp-cron.php — check if externally triggerable."""
        path = client.cron_path
        start = time.monotonic()
        try:
            status, body, headers = await client.get(path, cookies={})
            duration = (time.monotonic() - start) * 1000

            # wp-cron.php typically returns 200 with empty body when processing,
            # or takes a noticeable amount of time if executing cron events.
            if status == 200:
                return self._make_result(
                    variant="wp_cron_accessible",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"wp-cron.php accessible (HTTP {status}, {duration:.0f}ms)",
                    details=(
                        f"GET {path} returned HTTP {status} in {duration:.0f}ms. "
                        f"wp-cron.php is externally accessible and can be triggered "
                        f"by any unauthenticated user. This can be abused to trigger "
                        f"expensive cron jobs repeatedly for denial-of-service."
                    ),
                    request={"method": "GET", "path": path},
                    response={"status": status, "body": body[:200]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="wp_cron_accessible",
                status=Status.DEFENDED,
                evidence=f"wp-cron.php returned HTTP {status}",
                details=(
                    f"GET {path} returned HTTP {status}. "
                    f"wp-cron.php appears to be blocked or restricted."
                ),
                request={"method": "GET", "path": path},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="wp_cron_accessible",
                status=Status.ERROR,
                details=f"Error testing wp-cron.php accessibility: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # wp-cron.php DoS potential
    # ------------------------------------------------------------------
    async def _test_wp_cron_dos(self, client) -> AttackResult:
        """Send 5 rapid requests to wp-cron.php — measure processing times."""
        path = client.cron_path
        timings = []
        start_total = time.monotonic()

        try:
            for i in range(5):
                start = time.monotonic()
                status, body, headers = await client.get(path, cookies={})
                duration = (time.monotonic() - start) * 1000
                timings.append(duration)

            total_duration = (time.monotonic() - start_total) * 1000
            avg_time = sum(timings) / len(timings)
            max_time = max(timings)

            # If server processes each request (avg > 100ms or total > 1s),
            # it's processing cron events each time = DoS vector
            if avg_time > 100 or total_duration > 1000:
                return self._make_result(
                    variant="wp_cron_dos",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=(
                        f"5 rapid cron requests processed: avg={avg_time:.0f}ms, "
                        f"max={max_time:.0f}ms, total={total_duration:.0f}ms"
                    ),
                    details=(
                        f"Sent 5 rapid requests to {path}. "
                        f"Average response: {avg_time:.0f}ms, max: {max_time:.0f}ms, "
                        f"total: {total_duration:.0f}ms. Server appears to process "
                        f"cron events on each request without rate limiting. "
                        f"Repeated triggering can exhaust server resources."
                    ),
                    request={"method": "GET", "path": path, "count": 5},
                    response={"timings_ms": [round(t, 1) for t in timings]},
                    duration_ms=total_duration,
                )

            return self._make_result(
                variant="wp_cron_dos",
                status=Status.DEFENDED,
                evidence=(
                    f"Rapid cron requests handled efficiently: avg={avg_time:.0f}ms, "
                    f"total={total_duration:.0f}ms"
                ),
                details=(
                    f"5 rapid requests to {path} completed quickly "
                    f"(avg {avg_time:.0f}ms). Server appears to cache or rate-limit "
                    f"cron processing, reducing DoS potential."
                ),
                request={"method": "GET", "path": path, "count": 5},
                response={"timings_ms": [round(t, 1) for t in timings]},
                duration_ms=total_duration,
            )
        except Exception as e:
            return self._make_result(
                variant="wp_cron_dos",
                status=Status.ERROR,
                details=f"Error testing wp-cron DoS: {e}",
                duration_ms=(time.monotonic() - start_total) * 1000,
            )

    # ------------------------------------------------------------------
    # Cron event enumeration via REST API
    # ------------------------------------------------------------------
    async def _test_cron_event_enumeration(self, client) -> AttackResult:
        """Check REST API and admin-ajax.php for cron-related endpoints."""
        start = time.monotonic()
        cron_info = []

        try:
            # Check REST API index for cron-related routes
            status, body, headers = await client.rest_get(
                "/", authenticated=False
            )
            if status == 200 and "cron" in body.lower():
                cron_info.append("REST API index references cron endpoints")

            # Try wp/v2 cron-related endpoints
            for endpoint in ["/wp/v2/settings", "/wp-site-health/v1/tests"]:
                ep_status, ep_body, _ = await client.rest_get(
                    endpoint, authenticated=False
                )
                if ep_status == 200 and "cron" in ep_body.lower():
                    cron_info.append(f"{endpoint} exposes cron information")

            # Check admin-ajax.php for cron-related actions
            ajax_status, ajax_body, _ = await client.ajax_post(
                "wp-cron", authenticated=False
            )
            if ajax_status == 200 and ajax_body.strip() not in ("0", "-1", ""):
                cron_info.append("admin-ajax.php wp-cron action responsive")

            duration = (time.monotonic() - start) * 1000

            if cron_info:
                return self._make_result(
                    variant="cron_event_enumeration",
                    status=Status.VULNERABLE,
                    severity=Severity.INFO,
                    evidence=f"Cron information discovered: {cron_info}",
                    details=(
                        f"Enumerated cron-related information via REST API and AJAX. "
                        f"Findings: {'; '.join(cron_info)}. "
                        f"Exposed cron data helps attackers understand scheduled tasks."
                    ),
                    request={"method": "GET/POST", "targets": ["REST API", "admin-ajax.php"]},
                    response={"findings": cron_info},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="cron_event_enumeration",
                status=Status.DEFENDED,
                evidence="No cron information exposed via REST API or AJAX",
                details="REST API and admin-ajax.php do not expose cron-related data to unauthenticated users.",
                request={"method": "GET/POST", "targets": ["REST API", "admin-ajax.php"]},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="cron_event_enumeration",
                status=Status.ERROR,
                details=f"Error enumerating cron events: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ------------------------------------------------------------------
    # ALTERNATE_WP_CRON detection
    # ------------------------------------------------------------------
    async def _test_alternate_cron(self, client) -> AttackResult:
        """Check homepage for doing_wp_cron parameter indicating alternate cron."""
        start = time.monotonic()
        try:
            status, body, headers = await client.get("/", cookies={})
            duration = (time.monotonic() - start) * 1000

            match = DOING_CRON_RE.search(body)

            if match:
                return self._make_result(
                    variant="alternate_cron",
                    status=Status.VULNERABLE,
                    severity=Severity.INFO,
                    evidence="ALTERNATE_WP_CRON detected: doing_wp_cron parameter found in page",
                    details=(
                        f"Homepage contains 'doing_wp_cron' parameter in a URL or script tag. "
                        f"ALTERNATE_WP_CRON is likely enabled. This mode uses client-side "
                        f"redirects to trigger cron, which can leak timing information "
                        f"and is less reliable than server-side cron."
                    ),
                    request={"method": "GET", "path": "/"},
                    response={"status": status, "body": body[:500]},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="alternate_cron",
                status=Status.DEFENDED,
                evidence="No doing_wp_cron parameter found on homepage",
                details=(
                    "Homepage does not contain doing_wp_cron references. "
                    "ALTERNATE_WP_CRON does not appear to be enabled."
                ),
                request={"method": "GET", "path": "/"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="alternate_cron",
                status=Status.ERROR,
                details=f"Error testing alternate cron: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
