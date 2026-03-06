"""Session token predictability and entropy analysis — NIST SP 800-172 3.13.2e.

NIST SP 800-172 requirement 3.13.2e mandates that session identifiers and
authentication tokens be generated using approved random number generators
with sufficient entropy to prevent prediction by adversaries, including
Advanced Persistent Threats (APTs). Weak or predictable session tokens allow
an APT to enumerate valid sessions, forge tokens, or perform session fixation
attacks against CUI-handling systems.

This module tests:
  - JWT entropy and field predictability across rapid successive logins
  - Non-JWT session ID entropy (length and character diversity)
  - CSRF token uniqueness and randomness
  - Response header information leakage aiding session enumeration
  - Cookie security attributes preventing session hijacking
"""

import collections
import json
import math
import re
import time

import jwt as pyjwt

from redteam.base import Attack, AttackResult, Severity, Status


class SessionPredictabilityAttack(Attack):
    name = "api.session_predictability"
    category = "api"
    severity = Severity.HIGH
    description = (
        "NIST SP 800-172 3.13.2e — Analyze session token entropy and "
        "predictability; verify cookies carry proper security attributes"
    )

    # Minimum acceptable Shannon entropy (bits) for a session identifier
    MIN_ENTROPY_BITS = 3.5
    # Minimum length for a session identifier to be considered adequate
    MIN_SESSION_ID_LENGTH = 16

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _shannon_entropy(self, data: str) -> float:
        """Return Shannon entropy (bits per character) for *data*."""
        if not data:
            return 0.0
        freq = collections.Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _extract_session_cookies(self, headers: dict) -> dict[str, str]:
        """Parse Set-Cookie headers and return a {name: value} mapping."""
        cookies: dict[str, str] = {}
        raw = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
        # httpx/aiohttp may return a list; normalise to a single string
        if isinstance(raw, list):
            raw = "; ".join(raw)
        for segment in raw.split(","):
            segment = segment.strip()
            if not segment:
                continue
            # The first key=value pair is the cookie itself
            first = segment.split(";")[0].strip()
            if "=" in first:
                name, _, value = first.partition("=")
                cookies[name.strip()] = value.strip()
        return cookies

    # ------------------------------------------------------------------ #
    # Execute                                                              #
    # ------------------------------------------------------------------ #

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        results.append(await self._jwt_entropy_analysis(client))
        results.append(await self._session_id_entropy(client))
        results.append(await self._csrf_token_predictability(client))
        results.append(await self._response_header_info_leak(client))
        results.append(await self._cookie_security_attributes(client))

        return results

    # ------------------------------------------------------------------ #
    # Variant 1: JWT entropy analysis                                      #
    # ------------------------------------------------------------------ #

    async def _jwt_entropy_analysis(self, client) -> AttackResult:
        """Collect three JWTs in rapid succession and analyse claim entropy."""
        variant = "jwt_entropy_analysis"
        tokens: list[str] = []
        payloads: list[dict] = []

        for attempt in range(3):
            ok = await client.login(
                "redteam-sysadmin@test.com", "RedTeam$ysAdmin2026!"
            )
            if not ok:
                return self._make_result(
                    variant=variant,
                    status=Status.ERROR,
                    evidence=f"Login attempt {attempt + 1} failed.",
                    details="Cannot collect JWTs — login unavailable.",
                )
            token = client._cookies.get("eqmon_session", "")
            if not token:
                return self._make_result(
                    variant=variant,
                    status=Status.ERROR,
                    evidence=f"No eqmon_session cookie after login attempt {attempt + 1}.",
                    details="JWT not found in session cookie.",
                )
            tokens.append(token)

        # Decode all three without signature verification
        for token in tokens:
            try:
                claims = pyjwt.decode(
                    token, options={"verify_signature": False}
                )
                payloads.append(claims)
            except Exception as exc:
                return self._make_result(
                    variant=variant,
                    status=Status.ERROR,
                    evidence=f"JWT decode failed: {exc}",
                    details="Could not decode JWT payload for entropy analysis.",
                )

        findings: list[str] = []
        is_vulnerable = False

        # Check for identical iat values across rapid logins (batched clock)
        iats = [p.get("iat") for p in payloads if p.get("iat") is not None]
        if len(iats) == 3 and len(set(iats)) == 1:
            findings.append(
                f"All three JWTs share identical iat={iats[0]}. "
                "Token issuance timestamps are batched — no sub-second jitter. "
                "An APT could narrow the brute-force window significantly."
            )
            is_vulnerable = True

        # Check if jti/nonce fields are sequential or missing
        jtis = [p.get("jti") for p in payloads]
        if all(j is None for j in jtis):
            findings.append(
                "No jti (JWT ID) claim present in any token. "
                "Without a unique identifier per token, replay detection "
                "and token revocation are impractical."
            )
            is_vulnerable = True
        else:
            # jti present — check if they are sequential integers
            try:
                jti_ints = [int(j) for j in jtis if j is not None]
                if len(jti_ints) >= 2:
                    diffs = [
                        jti_ints[i + 1] - jti_ints[i]
                        for i in range(len(jti_ints) - 1)
                    ]
                    if all(d > 0 and d < 1000 for d in diffs):
                        findings.append(
                            f"jti values appear sequential: {jti_ints}. "
                            "Monotonically increasing integer JTIs allow an APT "
                            "to enumerate valid token identifiers."
                        )
                        is_vulnerable = True
                    else:
                        findings.append(
                            f"jti values present and non-sequential: {jtis}. "
                            "jti field appears adequately randomised."
                        )
            except (TypeError, ValueError):
                # Non-integer jtis — check entropy of the string values
                jti_strs = [j for j in jtis if isinstance(j, str)]
                for jti_val in jti_strs:
                    entropy = self._shannon_entropy(jti_val)
                    if entropy < self.MIN_ENTROPY_BITS:
                        findings.append(
                            f"jti='{jti_val}' has low Shannon entropy "
                            f"({entropy:.2f} bits/char < {self.MIN_ENTROPY_BITS} threshold)."
                        )
                        is_vulnerable = True

        # Check if user_id or sub is directly embedded and guessable
        user_ids = [p.get("user_id") or p.get("sub") for p in payloads]
        if all(isinstance(uid, int) for uid in user_ids if uid is not None):
            int_ids = [uid for uid in user_ids if uid is not None]
            if int_ids:
                findings.append(
                    f"user identifiers in JWT are integer primary keys: {int_ids}. "
                    "Sequential integer user IDs aid IDOR enumeration "
                    "when combined with predictable token structure."
                )
                # This is a contributing factor but not independently VULNERABLE

        status = Status.VULNERABLE if is_vulnerable else Status.DEFENDED
        if not findings:
            findings.append(
                "JWT claims appear sufficiently randomised across three rapid logins. "
                "iat values differ; jti (if present) is non-sequential."
            )

        evidence_parts = [
            f"Tokens collected: {len(tokens)}",
            f"iat values: {iats}",
            f"jti values: {jtis}",
            f"Payload keys: {list(payloads[0].keys()) if payloads else []}",
        ]

        return self._make_result(
            variant=variant,
            status=status,
            evidence=", ".join(evidence_parts),
            details=" | ".join(findings),
            request={"action": "login x3 rapid succession", "endpoint": "/api/auth/login.php"},
            response={"decoded_claims_sample": payloads[0] if payloads else {}},
        )

    # ------------------------------------------------------------------ #
    # Variant 2: Session ID entropy                                        #
    # ------------------------------------------------------------------ #

    async def _session_id_entropy(self, client) -> AttackResult:
        """Collect non-JWT cookies across multiple requests and measure entropy."""
        variant = "session_id_entropy"

        session_ids: list[str] = []
        raw_cookies_seen: list[dict] = []

        # Perform three logins and collect all non-JWT session cookies
        for _ in range(3):
            ok = await client.login(
                "redteam-sysadmin@test.com", "RedTeam$ysAdmin2026!"
            )
            if not ok:
                continue

            # Probe an authenticated endpoint to trigger session cookie issuance
            _code, _body, headers = await client.get(
                "/api/equipment.php",
                params={"action": "list"},
            )
            extracted = self._extract_session_cookies(headers)
            raw_cookies_seen.append(extracted)

            for name, value in extracted.items():
                # Skip well-known JWT cookies — those are tested in variant 1
                if name.lower() in ("eqmon_session",):
                    continue
                # Skip empty values and purely numeric short values
                if value and len(value) > 4:
                    session_ids.append(value)

        if not session_ids:
            # No non-JWT session identifiers found — check if that itself is notable
            return self._make_result(
                variant=variant,
                status=Status.DEFENDED,
                evidence="No non-JWT session identifiers found in response cookies.",
                details=(
                    "Application appears to rely solely on JWT-based authentication "
                    "with no supplementary session cookies. "
                    "This reduces the session ID attack surface."
                ),
                request={"action": "login + GET /api/equipment.php x3"},
                response={"cookies_observed": raw_cookies_seen},
            )

        findings: list[str] = []
        is_vulnerable = False

        for sid in session_ids:
            if len(sid) < self.MIN_SESSION_ID_LENGTH:
                findings.append(
                    f"Session ID '{sid[:8]}...' is only {len(sid)} characters "
                    f"(minimum recommended: {self.MIN_SESSION_ID_LENGTH}). "
                    "Short identifiers are brute-forceable."
                )
                is_vulnerable = True

            entropy = self._shannon_entropy(sid)
            charset_size = len(set(sid))
            if entropy < self.MIN_ENTROPY_BITS:
                findings.append(
                    f"Session ID '{sid[:8]}...' has Shannon entropy "
                    f"{entropy:.2f} bits/char using only {charset_size} distinct "
                    f"characters. Low entropy makes token prediction feasible."
                )
                is_vulnerable = True
            else:
                findings.append(
                    f"Session ID '{sid[:8]}...' length={len(sid)}, "
                    f"entropy={entropy:.2f} bits/char, charset_size={charset_size} — adequate."
                )

        # Check if all collected IDs are identical (no randomisation)
        if len(set(session_ids)) == 1 and len(session_ids) > 1:
            findings.append(
                "All collected session IDs are identical across separate logins. "
                "Static session identifiers are trivially predictable."
            )
            is_vulnerable = True

        status = Status.VULNERABLE if is_vulnerable else Status.DEFENDED
        return self._make_result(
            variant=variant,
            status=status,
            evidence=(
                f"Non-JWT session IDs collected: {len(session_ids)}, "
                f"unique values: {len(set(session_ids))}, "
                f"sample length: {len(session_ids[0]) if session_ids else 0}"
            ),
            details=" | ".join(findings),
            request={"action": "login + probe x3"},
            response={"session_id_count": len(session_ids), "unique": len(set(session_ids))},
        )

    # ------------------------------------------------------------------ #
    # Variant 3: CSRF token predictability                                 #
    # ------------------------------------------------------------------ #

    async def _csrf_token_predictability(self, client) -> AttackResult:
        """Fetch form pages multiple times and analyse CSRF token randomness."""
        variant = "csrf_token_predictability"

        # Candidate pages that typically embed CSRF tokens
        candidate_paths = [
            "/admin/login.php",
            "/login.php",
            "/admin/index.php",
            "/index.php",
            "/api/auth/login.php",
        ]
        # Regex patterns for common CSRF token field names
        csrf_pattern = re.compile(
            r'(?:csrf[_-]?token|_token|nonce|authenticity_token)'
            r'["\']?\s*(?:value\s*=\s*|:\s*)["\']([A-Za-z0-9+/=_\-]{8,})["\']',
            re.IGNORECASE,
        )

        csrf_tokens: list[str] = []
        pages_tried: list[str] = []

        for path in candidate_paths:
            for _ in range(3):
                code, body, _headers = await client.get(path)
                if code == 200 and isinstance(body, str):
                    matches = csrf_pattern.findall(body)
                    csrf_tokens.extend(matches)
                    if matches:
                        pages_tried.append(path)
                        break  # found on this page, move on

        if not csrf_tokens:
            return self._make_result(
                variant=variant,
                status=Status.DEFENDED,
                evidence=(
                    f"No CSRF tokens found in HTML responses from: "
                    f"{', '.join(candidate_paths)}"
                ),
                details=(
                    "No CSRF token fields detected in form pages. "
                    "The application may use header-based CSRF protection "
                    "(e.g., SameSite cookies, custom request headers) or "
                    "the pages are not accessible without authentication."
                ),
                request={"paths_probed": candidate_paths, "attempts_each": 3},
                response={"tokens_found": 0},
            )

        findings: list[str] = []
        is_vulnerable = False

        # Check for duplicate tokens across separate fetches
        unique_tokens = set(csrf_tokens)
        if len(unique_tokens) < len(csrf_tokens):
            duplicates = len(csrf_tokens) - len(unique_tokens)
            findings.append(
                f"{duplicates} duplicate CSRF token(s) detected across separate requests. "
                "Reused CSRF tokens are vulnerable to CSRF attacks and token fixation."
            )
            is_vulnerable = True

        # Check entropy of each unique token
        for tok in unique_tokens:
            entropy = self._shannon_entropy(tok)
            if len(tok) < 16:
                findings.append(
                    f"CSRF token '{tok[:8]}...' is only {len(tok)} characters — too short."
                )
                is_vulnerable = True
            elif entropy < self.MIN_ENTROPY_BITS:
                findings.append(
                    f"CSRF token '{tok[:8]}...' has low entropy ({entropy:.2f} bits/char)."
                )
                is_vulnerable = True
            else:
                findings.append(
                    f"CSRF token '{tok[:8]}...' length={len(tok)}, "
                    f"entropy={entropy:.2f} bits/char — appears adequately random."
                )

        status = Status.VULNERABLE if is_vulnerable else Status.DEFENDED
        return self._make_result(
            variant=variant,
            status=status,
            evidence=(
                f"CSRF tokens collected: {len(csrf_tokens)}, "
                f"unique: {len(unique_tokens)}, "
                f"from pages: {list(set(pages_tried))}"
            ),
            details=" | ".join(findings),
            request={"paths": pages_tried},
            response={"tokens_found": len(csrf_tokens), "unique_count": len(unique_tokens)},
        )

    # ------------------------------------------------------------------ #
    # Variant 4: Response header information leak                          #
    # ------------------------------------------------------------------ #

    async def _response_header_info_leak(self, client) -> AttackResult:
        """Check response headers for server version disclosure and sequential IDs."""
        variant = "response_header_info_leak"

        code, _body, headers = await client.get("/api/equipment.php", params={"action": "list"})

        # Normalise header names to lower-case for consistent lookup
        norm: dict[str, str] = {k.lower(): v for k, v in headers.items()}

        findings: list[str] = []
        is_vulnerable = False
        is_partial = False

        # Server version disclosure
        server_header = norm.get("server", "")
        if server_header:
            # Presence of a version number (e.g., "Apache/2.4.52") is a finding
            if re.search(r"/[\d.]+", server_header):
                findings.append(
                    f"Server header exposes version: '{server_header}'. "
                    "Precise version information aids APT vulnerability research."
                )
                is_partial = True
            else:
                findings.append(
                    f"Server header present but no version: '{server_header}'."
                )

        # X-Powered-By
        powered_by = norm.get("x-powered-by", "")
        if powered_by:
            findings.append(
                f"X-Powered-By header present: '{powered_by}'. "
                "Technology stack disclosure assists fingerprinting."
            )
            is_partial = True

        # X-Debug-Token (development artifact)
        debug_token = norm.get("x-debug-token", "") or norm.get("x-debug-token-link", "")
        if debug_token:
            findings.append(
                f"X-Debug-Token header present: '{debug_token}'. "
                "Debug tokens in production indicate insufficient hardening."
            )
            is_vulnerable = True

        # X-Request-Id — check if sequential across multiple requests
        request_ids: list[str] = []
        for _ in range(3):
            _c, _b, h = await client.get("/api/equipment.php", params={"action": "list"})
            hn = {k.lower(): v for k, v in h.items()}
            rid = hn.get("x-request-id", "")
            if rid:
                request_ids.append(rid)

        if request_ids:
            try:
                int_ids = [int(r) for r in request_ids]
                diffs = [int_ids[i + 1] - int_ids[i] for i in range(len(int_ids) - 1)]
                if all(0 < d < 100 for d in diffs):
                    findings.append(
                        f"X-Request-Id appears sequential: {int_ids}. "
                        "Sequential request IDs expose request volume and aid "
                        "timing-based session correlation attacks."
                    )
                    is_partial = True
                else:
                    findings.append(
                        f"X-Request-Id values not strictly sequential: {request_ids}."
                    )
            except (TypeError, ValueError):
                # Non-integer request IDs — check entropy
                for rid in request_ids:
                    entropy = self._shannon_entropy(rid)
                    if entropy < self.MIN_ENTROPY_BITS:
                        findings.append(
                            f"X-Request-Id '{rid[:12]}...' has low entropy "
                            f"({entropy:.2f} bits/char)."
                        )
                        is_partial = True

        if not findings:
            findings.append(
                "No significant information-leaking headers detected. "
                "Server, X-Powered-By, and X-Debug-Token headers absent or clean."
            )

        if is_vulnerable:
            status = Status.VULNERABLE
        elif is_partial:
            status = Status.PARTIAL
        else:
            status = Status.DEFENDED

        exposed = {
            k: norm[k]
            for k in ("server", "x-powered-by", "x-debug-token", "x-request-id")
            if k in norm
        }
        return self._make_result(
            variant=variant,
            status=status,
            severity=Severity.MEDIUM,
            evidence=(
                f"HTTP status: {code}, "
                f"Leaking headers: {list(exposed.keys()) or 'none'}, "
                f"X-Request-Id samples: {request_ids or 'none'}"
            ),
            details=" | ".join(findings),
            request={"endpoint": "/api/equipment.php", "method": "GET"},
            response={"exposed_headers": exposed},
        )

    # ------------------------------------------------------------------ #
    # Variant 5: Cookie security attributes                                #
    # ------------------------------------------------------------------ #

    async def _cookie_security_attributes(self, client) -> AttackResult:
        """Login and verify Set-Cookie headers carry HttpOnly, Secure, SameSite."""
        variant = "cookie_security_attributes"

        ok = await client.login(
            "redteam-sysadmin@test.com", "RedTeam$ysAdmin2026!"
        )
        if not ok:
            return self._make_result(
                variant=variant,
                status=Status.ERROR,
                evidence="Login failed — cannot inspect Set-Cookie headers.",
                details="Authentication unavailable for cookie attribute inspection.",
            )

        # Re-issue the login request directly to capture raw Set-Cookie headers
        _code, _body, headers = await client.post(
            "/api/auth/login.php",
            json_body={
                "email": "redteam-sysadmin@test.com",
                "password": "RedTeam$ysAdmin2026!",
                "action": "login",
            },
        )

        # Collect raw Set-Cookie strings
        raw_set_cookie = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
        if isinstance(raw_set_cookie, list):
            cookie_strings = raw_set_cookie
        else:
            cookie_strings = [raw_set_cookie] if raw_set_cookie else []

        # Also probe an authenticated endpoint which may set additional cookies
        _c2, _b2, h2 = await client.get(
            "/api/equipment.php", params={"action": "list"}
        )
        extra = h2.get("Set-Cookie", "") or h2.get("set-cookie", "")
        if extra:
            if isinstance(extra, list):
                cookie_strings.extend(extra)
            else:
                cookie_strings.append(extra)

        if not cookie_strings or all(not s.strip() for s in cookie_strings):
            return self._make_result(
                variant=variant,
                status=Status.ERROR,
                evidence="No Set-Cookie headers captured in login or authenticated response.",
                details="Could not inspect cookie security attributes.",
            )

        findings: list[str] = []
        missing_httponly = False
        missing_secure = False
        missing_samesite = False

        for raw in cookie_strings:
            if not raw.strip():
                continue

            # Extract cookie name from first segment
            first_segment = raw.split(";")[0].strip()
            cookie_name = first_segment.split("=")[0].strip() if "=" in first_segment else first_segment

            directives = raw.lower()

            has_httponly = "httponly" in directives
            has_secure = "secure" in directives
            samesite_match = re.search(r"samesite\s*=\s*(\w+)", directives)
            samesite_val = samesite_match.group(1) if samesite_match else None

            cookie_findings: list[str] = []

            if not has_httponly:
                cookie_findings.append("missing HttpOnly (XSS can exfiltrate this cookie)")
                missing_httponly = True

            if not has_secure:
                cookie_findings.append("missing Secure (plaintext transmission possible)")
                missing_secure = True

            if samesite_val is None:
                cookie_findings.append("missing SameSite (CSRF protection absent)")
                missing_samesite = True
            elif samesite_val == "none":
                cookie_findings.append("SameSite=None (CSRF protection disabled)")
                missing_samesite = True
            elif samesite_val in ("strict", "lax"):
                pass  # acceptable

            if cookie_findings:
                findings.append(
                    f"Cookie '{cookie_name}': " + "; ".join(cookie_findings) + "."
                )
            else:
                findings.append(
                    f"Cookie '{cookie_name}': HttpOnly=yes, Secure=yes, "
                    f"SameSite={samesite_val} — all security attributes present."
                )

        if missing_httponly or missing_secure:
            status = Status.VULNERABLE
        elif missing_samesite:
            status = Status.PARTIAL
        else:
            status = Status.DEFENDED

        return self._make_result(
            variant=variant,
            status=status,
            evidence=(
                f"Cookies inspected: {len(cookie_strings)}, "
                f"missing HttpOnly: {missing_httponly}, "
                f"missing Secure: {missing_secure}, "
                f"missing SameSite: {missing_samesite}"
            ),
            details=" | ".join(findings) if findings else "No cookie attribute issues found.",
            request={"action": "login + GET /api/equipment.php"},
            response={
                "cookies_checked": len(cookie_strings),
                "missing_httponly": missing_httponly,
                "missing_secure": missing_secure,
                "missing_samesite": missing_samesite,
            },
        )
