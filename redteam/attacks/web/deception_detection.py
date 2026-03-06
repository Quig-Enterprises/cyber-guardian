"""Deception mechanism detection tests (NIST SP 800-172 3.13.3e).

Tests whether the organization has deployed deception mechanisms per NIST 800-172
requirement 3.13.3e: employ deception techniques and technologies to confuse and
mislead adversaries. Absence of deception = PARTIAL (org not using 800-172 controls).
Presence of deception indicators = DEFENDED.

Variants:
- honeypot_endpoints: Probe for decoy paths that should exist if org deploys honeypots
- honeytoken_in_responses: Check API responses for embedded honeytoken markers
- decoy_credentials_check: Look for tracking pixels, beacon scripts, decoy form fields
- robots_txt_deception: Inspect robots.txt for deliberate lure/decoy Disallow entries
- fake_error_responses: Evaluate error responses for deliberate misdirection patterns
"""

import json
import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class DeceptionDetectionAttack(Attack):
    """NIST 800-172 3.13.3e — Verify deception mechanisms are deployed."""

    name = "web.deception_detection"
    category = "web"
    severity = Severity.MEDIUM
    description = (
        "NIST 800-172 3.13.3e — Verify deception mechanisms are deployed to "
        "confuse/mislead adversaries"
    )

    # Paths that an APT-aware org should have as honeypot decoys
    _HONEYPOT_PATHS = [
        "/admin/backup.php",
        "/api/internal/debug",
        "/wp-admin/",
        "/phpmyadmin/",
        "/.git/config",
        "/api/v1/tokens",
    ]

    # Regex patterns indicating intentional honeytoken markers
    _HONEYTOKEN_PATTERNS = [
        re.compile(r"\bcanary[-_][a-zA-Z0-9]{4,}\b"),
        re.compile(r"\bhoney[-_][a-zA-Z0-9]{4,}\b"),
        re.compile(r"\btrap[-_][a-zA-Z0-9]{4,}\b"),
        re.compile(r"\btoken[-_][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
        re.compile(r"\bhoneypot\b", re.I),
        re.compile(r"\bdeckoy\b", re.I),  # deliberate misspelling as a trap marker
    ]

    # Endpoints commonly holding user/data objects where honeytokens may live
    _DATA_ENDPOINTS = [
        "/api/users",
        "/api/user",
        "/api/profile",
        "/api/me",
        "/api/account",
        "/api/data",
    ]

    # Patterns suggesting deliberate deceptive error content
    _MISDIRECTION_PATTERNS = [
        re.compile(r"stack trace", re.I),          # Fake stack traces waste attacker time
        re.compile(r"database error", re.I),        # Fake DB errors misdirect
        re.compile(r"internal server error.*line \d+", re.I),
        re.compile(r"debug_mode\s*=\s*true", re.I),
        re.compile(r"secret[_\s]key\s*[:=]", re.I),  # Fake leaked secrets
        re.compile(r"password\s*[:=]\s*['\"][^'\"]{6,}", re.I),
    ]

    async def execute(self, client) -> list[AttackResult]:
        """Run all deception detection variants."""
        results = []
        results.append(await self._test_honeypot_endpoints(client))
        results.append(await self._test_honeytoken_in_responses(client))
        results.append(await self._test_decoy_credentials_check(client))
        results.append(await self._test_robots_txt_deception(client))
        results.append(await self._test_fake_error_responses(client))
        return results

    async def _test_honeypot_endpoints(self, client) -> AttackResult:
        """Probe for honeypot/decoy paths — a deployed org should have plausible-looking ones."""
        start = time.monotonic()
        try:
            defended_paths = []
            missing_paths = []

            for path in self._HONEYPOT_PATHS:
                status_code, body, headers = await client.get(path)
                content_type = headers.get("Content-Type", "")
                body_text = body if isinstance(body, str) else (body.decode("utf-8", errors="replace") if body else "")

                # A honeypot endpoint looks plausible: 200 with crafted content
                # (not just a redirect to login or a generic 404)
                if status_code == 200 and len(body_text) > 50:
                    defended_paths.append(f"{path} (200, {len(body_text)} bytes)")
                    logger.debug("Potential honeypot endpoint detected: %s", path)
                else:
                    missing_paths.append(f"{path} ({status_code})")

            duration = (time.monotonic() - start) * 1000

            if defended_paths:
                return self._make_result(
                    variant="honeypot_endpoints",
                    status=Status.DEFENDED,
                    evidence=f"Plausible honeypot endpoints detected: {', '.join(defended_paths)}",
                    details=(
                        "Organization appears to have deployed decoy endpoints returning "
                        "crafted content — consistent with NIST 800-172 3.13.3e deception controls."
                    ),
                    request={"probed_paths": self._HONEYPOT_PATHS},
                    response={
                        "honeypot_candidates": defended_paths,
                        "missing_decoys": missing_paths,
                    },
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="honeypot_endpoints",
                    status=Status.PARTIAL,
                    evidence=f"None of {len(self._HONEYPOT_PATHS)} probed decoy paths returned plausible responses",
                    details=(
                        "No honeypot/decoy endpoints detected. NIST 800-172 3.13.3e requires "
                        "deception mechanisms to confuse adversaries. Organization should deploy "
                        "realistic-looking decoy endpoints that trigger alerts on access."
                    ),
                    request={"probed_paths": self._HONEYPOT_PATHS},
                    response={"path_responses": missing_paths},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="honeypot_endpoints",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_honeytoken_in_responses(self, client) -> AttackResult:
        """Check API responses for embedded honeytoken markers (trackable fake data)."""
        start = time.monotonic()
        try:
            honeytoken_hits = []
            endpoints_checked = []

            for endpoint in self._DATA_ENDPOINTS:
                try:
                    status_code, body, headers = await client.get(endpoint)
                    endpoints_checked.append(endpoint)

                    body_text = body if isinstance(body, str) else (
                        body.decode("utf-8", errors="replace") if body else ""
                    )

                    # Try to parse as JSON for structured inspection
                    body_str = body_text
                    try:
                        parsed = json.loads(body_text)
                        body_str = json.dumps(parsed)
                    except (json.JSONDecodeError, TypeError):
                        pass

                    for pattern in self._HONEYTOKEN_PATTERNS:
                        match = pattern.search(body_str)
                        if match:
                            honeytoken_hits.append({
                                "endpoint": endpoint,
                                "pattern": pattern.pattern,
                                "match": match.group(0),
                            })
                            logger.debug(
                                "Honeytoken pattern '%s' found in %s", pattern.pattern, endpoint
                            )
                            break  # One hit per endpoint is enough
                except Exception:
                    pass  # Endpoint may not exist; continue

            duration = (time.monotonic() - start) * 1000

            if honeytoken_hits:
                hit_summary = [f"{h['endpoint']} (matched: {h['match']})" for h in honeytoken_hits]
                return self._make_result(
                    variant="honeytoken_in_responses",
                    status=Status.DEFENDED,
                    evidence=f"Honeytoken markers found in API responses: {', '.join(hit_summary)}",
                    details=(
                        "API responses contain what appear to be honeytoken markers. "
                        "This is consistent with 800-172 3.13.3e deception deployment — "
                        "tracked fake data that alerts when exfiltrated or reused."
                    ),
                    request={"endpoints_checked": endpoints_checked},
                    response={"honeytoken_hits": honeytoken_hits},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="honeytoken_in_responses",
                    status=Status.PARTIAL,
                    evidence="No honeytoken markers detected in API response fields",
                    details=(
                        "No trackable honeytoken data found in API responses. "
                        "NIST 800-172 3.13.3e recommends embedding trackable fake credentials "
                        "or tokens that trigger alerts when accessed or exfiltrated."
                    ),
                    request={"endpoints_checked": endpoints_checked},
                    response={"honeytoken_hits": []},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="honeytoken_in_responses",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_decoy_credentials_check(self, client) -> AttackResult:
        """Check login pages and error responses for decoy credentials or tracking beacons."""
        start = time.monotonic()
        try:
            login_paths = ["/login", "/signin", "/auth", "/admin/login", "/api/login"]
            deception_indicators = []

            # Patterns suggesting tracking/deception in HTML
            tracking_patterns = [
                (re.compile(r'<input[^>]+type=["\']hidden["\'][^>]+name=["\'][^"\']*(?:trap|decoy|canary|honey)[^"\']*["\']', re.I),
                 "hidden decoy form field"),
                (re.compile(r'<img[^>]+(?:width|height)=["\']0["\'][^>]+src=["\'][^"\']+["\']', re.I),
                 "zero-dimension tracking pixel"),
                (re.compile(r'<img[^>]+src=["\'][^"\']*(?:beacon|track|pixel|canary)[^"\']*["\']', re.I),
                 "named tracking/beacon image"),
                (re.compile(r'<script[^>]+src=["\'][^"\']*(?:beacon|track|canary)[^"\']*["\']', re.I),
                 "tracking/beacon script"),
                (re.compile(r'navigator\.sendBeacon\s*\(', re.I),
                 "sendBeacon() call (potential tracking)"),
                (re.compile(r'fetch\s*\(\s*["\'][^"\']*(?:beacon|canary|track)[^"\']*["\']', re.I),
                 "fetch() to beacon/tracking endpoint"),
                (re.compile(r'<!--.*(?:canary|honey|trap|decoy).*-->', re.I),
                 "deception comment marker"),
            ]

            for path in login_paths:
                try:
                    status_code, body, headers = await client.get(path)
                    body_text = body if isinstance(body, str) else (
                        body.decode("utf-8", errors="replace") if body else ""
                    )

                    if not body_text or status_code not in (200, 401, 403):
                        continue

                    for pattern, label in tracking_patterns:
                        if pattern.search(body_text):
                            deception_indicators.append({
                                "path": path,
                                "indicator": label,
                                "status_code": status_code,
                            })
                            logger.debug("Deception indicator '%s' found at %s", label, path)
                except Exception:
                    pass

            duration = (time.monotonic() - start) * 1000

            if deception_indicators:
                summary = [f"{d['path']}: {d['indicator']}" for d in deception_indicators]
                return self._make_result(
                    variant="decoy_credentials_check",
                    status=Status.DEFENDED,
                    evidence=f"Deception/tracking indicators found: {'; '.join(summary)}",
                    details=(
                        "Login pages contain deception elements such as tracking pixels, "
                        "beacon scripts, or hidden decoy fields. Consistent with 800-172 "
                        "3.13.3e requirement to employ deception technologies."
                    ),
                    request={"checked_paths": login_paths},
                    response={"indicators": deception_indicators},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="decoy_credentials_check",
                    status=Status.PARTIAL,
                    evidence="No decoy credentials, tracking pixels, or beacon scripts found in login pages",
                    details=(
                        "Login and auth pages contain no detectable deception elements. "
                        "NIST 800-172 3.13.3e recommends deploying decoy content (tracking "
                        "pixels, beacon scripts, hidden decoy fields) to detect unauthorized access."
                    ),
                    request={"checked_paths": login_paths},
                    response={"indicators": []},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="decoy_credentials_check",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_robots_txt_deception(self, client) -> AttackResult:
        """Check robots.txt for deliberate deceptive/lure Disallow entries."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get("/robots.txt")
            duration = (time.monotonic() - start) * 1000

            body_text = body if isinstance(body, str) else (
                body.decode("utf-8", errors="replace") if body else ""
            )

            if status_code != 200 or not body_text.strip():
                return self._make_result(
                    variant="robots_txt_deception",
                    status=Status.PARTIAL,
                    evidence=f"/robots.txt returned {status_code} or empty body",
                    details=(
                        "No robots.txt found or empty. A deception-aware org should include "
                        "deliberate lure entries (tempting Disallow paths like /admin/secrets, "
                        "/backup/, /internal/) to attract and fingerprint attackers per 800-172 3.13.3e."
                    ),
                    request={"path": "/robots.txt"},
                    response={"status_code": status_code, "body_length": len(body_text)},
                    duration_ms=duration,
                )

            disallow_entries = re.findall(r"^Disallow:\s*(.+)$", body_text, re.MULTILINE | re.I)

            # Lure patterns — paths designed to attract attackers
            lure_patterns = [
                re.compile(r"/(admin|administrator|root)(?:/|$)", re.I),
                re.compile(r"/(backup|bak|dump|export)(?:/|$)", re.I),
                re.compile(r"/(secret|private|internal|hidden|confidential)(?:/|$)", re.I),
                re.compile(r"/(config|configuration|settings|env)(?:/|$)", re.I),
                re.compile(r"/(db|database|sql|data)(?:/|$)", re.I),
                re.compile(r"/(api/v\d+/internal|api/debug|api/test)(?:/|$)", re.I),
                re.compile(r"/\.(git|svn|env|htpasswd)(?:/|$)", re.I),
            ]

            lure_entries = []
            standard_entries = []

            for entry in disallow_entries:
                entry = entry.strip()
                is_lure = any(p.search(entry) for p in lure_patterns)
                if is_lure:
                    lure_entries.append(entry)
                else:
                    standard_entries.append(entry)

            # A deception strategy needs multiple tempting paths
            if len(lure_entries) >= 2:
                return self._make_result(
                    variant="robots_txt_deception",
                    status=Status.DEFENDED,
                    evidence=f"robots.txt contains {len(lure_entries)} apparent lure/decoy Disallow entries: {lure_entries}",
                    details=(
                        "robots.txt includes multiple high-value-looking Disallow paths that "
                        "would attract attacker enumeration, consistent with 800-172 3.13.3e "
                        "deception strategy of drawing adversaries toward monitored decoys."
                    ),
                    request={"path": "/robots.txt"},
                    response={
                        "lure_entries": lure_entries,
                        "standard_entries": standard_entries,
                        "total_disallows": len(disallow_entries),
                    },
                    duration_ms=duration,
                )
            elif len(lure_entries) == 1:
                return self._make_result(
                    variant="robots_txt_deception",
                    status=Status.PARTIAL,
                    evidence=f"Only one possible lure entry in robots.txt: {lure_entries}",
                    details=(
                        "robots.txt has limited deceptive entries. A robust 800-172 3.13.3e "
                        "implementation should include multiple tempting decoy paths to maximize "
                        "attacker engagement and improve detection coverage."
                    ),
                    request={"path": "/robots.txt"},
                    response={
                        "lure_entries": lure_entries,
                        "standard_entries": standard_entries,
                    },
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="robots_txt_deception",
                    status=Status.PARTIAL,
                    evidence=f"robots.txt present but contains only standard/generic Disallow entries: {standard_entries}",
                    details=(
                        "robots.txt exists but lacks deliberate deception lure paths. "
                        "Per NIST 800-172 3.13.3e, robots.txt should include tempting "
                        "decoy paths (/backup/, /internal/, /.git/) to detect and misdirect "
                        "attacker enumeration."
                    ),
                    request={"path": "/robots.txt"},
                    response={
                        "disallow_entries": disallow_entries,
                        "lure_entries": [],
                    },
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="robots_txt_deception",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_fake_error_responses(self, client) -> AttackResult:
        """Send bad requests and check if errors contain deliberate misdirection."""
        start = time.monotonic()
        try:
            # Intentionally malformed/provocative requests designed to trigger errors
            bad_requests = [
                ("/api/nonexistent-endpoint-xyz", {}),
                ("/api/users/../../../../etc/passwd", {}),
                ("/api/" + "A" * 512, {}),  # Long path to trigger path errors
                ("/api/users?id=1' OR '1'='1", {}),  # SQL injection attempt
                ("/api/exec?cmd=id", {}),  # RCE probe
            ]

            misdirection_hits = []
            generic_errors = []
            error_response_samples = []

            for path, params in bad_requests:
                try:
                    status_code, body, headers = await client.get(path, params=params)
                    body_text = body if isinstance(body, str) else (
                        body.decode("utf-8", errors="replace") if body else ""
                    )

                    if not body_text or status_code == 200:
                        continue

                    error_response_samples.append({
                        "path": path,
                        "status_code": status_code,
                        "body_preview": body_text[:200],
                    })

                    # Check for deliberate misdirection patterns
                    for pattern in self._MISDIRECTION_PATTERNS:
                        if pattern.search(body_text):
                            misdirection_hits.append({
                                "path": path,
                                "status_code": status_code,
                                "pattern": pattern.pattern,
                                "body_preview": body_text[:150],
                            })
                            logger.debug(
                                "Misdirection pattern '%s' in error response from %s",
                                pattern.pattern, path
                            )
                            break
                    else:
                        generic_errors.append(f"{path} ({status_code})")

                except Exception:
                    pass

            duration = (time.monotonic() - start) * 1000

            if misdirection_hits:
                summary = [
                    f"{h['path']}: matched '{h['pattern']}'" for h in misdirection_hits
                ]
                return self._make_result(
                    variant="fake_error_responses",
                    status=Status.DEFENDED,
                    evidence=f"Misdirection content detected in {len(misdirection_hits)} error responses: {'; '.join(summary)}",
                    details=(
                        "Error responses contain deliberate misdirection content (fake stack traces, "
                        "false credential leaks, or fabricated debug info). This is consistent with "
                        "NIST 800-172 3.13.3e deception — wasting attacker reconnaissance time "
                        "with misleading information."
                    ),
                    request={"probed_paths": [r[0] for r in bad_requests]},
                    response={
                        "misdirection_hits": misdirection_hits,
                        "generic_error_count": len(generic_errors),
                    },
                    duration_ms=duration,
                )
            elif error_response_samples:
                return self._make_result(
                    variant="fake_error_responses",
                    status=Status.PARTIAL,
                    evidence=f"Error responses are generic/standard — no deliberate misdirection detected across {len(error_response_samples)} responses",
                    details=(
                        "Error responses return standard, accurate error information without "
                        "deceptive content. NIST 800-172 3.13.3e recommends crafting error "
                        "responses that mislead attackers (e.g., fake stack traces, false "
                        "technology indicators) to waste adversary time and improve detection."
                    ),
                    request={"probed_paths": [r[0] for r in bad_requests]},
                    response={
                        "misdirection_hits": [],
                        "sample_responses": error_response_samples[:3],
                    },
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="fake_error_responses",
                    status=Status.PARTIAL,
                    evidence="No error responses returned body content suitable for misdirection analysis",
                    details=(
                        "Could not obtain error responses with body content. "
                        "Unable to assess deceptive error handling per 800-172 3.13.3e."
                    ),
                    request={"probed_paths": [r[0] for r in bad_requests]},
                    response={"error_response_samples": error_response_samples},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="fake_error_responses",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by deception detection tests."""
        pass
