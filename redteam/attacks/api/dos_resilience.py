"""DoS resilience attacks - resource exhaustion and input size limit testing."""

import asyncio
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status

# Timeout threshold (seconds) above which a response is considered excessive
EXCESSIVE_TIMEOUT_SEC = 60.0


class DosResilienceAttack(Attack):
    name = "api.dos_resilience"
    category = "api"
    severity = Severity.MEDIUM
    description = "DoS resilience: resource exhaustion and input size limit testing against the AI chat endpoint"
    target_types = {"app", "wordpress", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        # In AWS mode this entire attack is skipped to avoid throttling EC2 resources.
        if self._is_aws_mode():
            return [self._make_result(
                variant="skipped_aws_mode",
                status=Status.SKIPPED,
                evidence="Attack skipped: execution mode is 'aws'.",
                details=(
                    "DoS resilience tests are disabled in AWS mode to prevent resource "
                    "exhaustion on EC2 instances and avoid triggering AWS abuse detection."
                ),
            )]

        results = []
        self._test_path = self._get_test_endpoints()[0]

        results.append(await self._test_long_prompt(client))
        results.append(await self._test_deeply_nested_json(client))
        results.append(await self._test_many_fields_json(client))
        results.append(await self._test_repeated_special_chars(client))
        results.append(await self._test_rapid_fire_chat(client))

        return results

    # ------------------------------------------------------------------
    # Variant 1: long_prompt
    # ------------------------------------------------------------------
    async def _test_long_prompt(self, client) -> AttackResult:
        """Send a 100 KB message to the chat endpoint.

        Expected: server should reject with 413 or 400 (input length validation).
        PARTIAL: server accepts without validation but handles it gracefully.
        VULNERABLE: server crashes (500) or hangs (>60 s timeout).
        """
        session_id = f"redteam-dos-longprompt-{uuid.uuid4().hex[:8]}"
        message = "A" * (100 * 1024)  # 100 KB

        start = time.monotonic()
        try:
            status_code, body, headers = await client.post(
                self._test_path,
                json_body={
                    "action": "send_message",
                    "message": message,
                    "session_id": session_id,
                },
            )
            duration_ms = (time.monotonic() - start) * 1000
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            return self._make_result(
                variant="long_prompt",
                status=Status.VULNERABLE,
                evidence=f"Exception after {duration_ms:.0f} ms: {exc}",
                details=(
                    "Sent 100 KB message. Client raised an exception — server likely crashed "
                    "or the connection was forcibly reset."
                ),
                request={"message_size": "100 KB", "session_id": session_id},
                response={"error": str(exc)},
                duration_ms=duration_ms,
            )

        duration_sec = duration_ms / 1000.0

        if status_code in (413, 400, 422):
            result_status = Status.DEFENDED
            details = (
                f"Server correctly rejected 100 KB prompt with {status_code}. "
                "Input length validation is in place."
            )
        elif status_code == 500:
            result_status = Status.VULNERABLE
            details = (
                f"Server returned 500 for a 100 KB prompt after {duration_sec:.1f} s. "
                "This indicates resource exhaustion or an unhandled error."
            )
        elif duration_sec > EXCESSIVE_TIMEOUT_SEC:
            result_status = Status.VULNERABLE
            details = (
                f"Server accepted 100 KB prompt and took {duration_sec:.1f} s to respond. "
                "No input length limit detected; response time exceeds 60 s threshold."
            )
        elif status_code == 200:
            result_status = Status.PARTIAL
            details = (
                f"Server accepted 100 KB prompt and responded in {duration_sec:.1f} s "
                f"(status 200). No input length validation detected — large inputs are "
                "forwarded to Ollama without restriction."
            )
        else:
            result_status = Status.PARTIAL
            details = (
                f"Unexpected status {status_code} for 100 KB prompt after {duration_sec:.1f} s."
            )

        return self._make_result(
            variant="long_prompt",
            status=result_status,
            evidence=f"Status: {status_code}, duration: {duration_sec:.2f} s, body: {body[:200]}",
            details=details,
            request={"message_size": "100 KB (102400 chars)", "session_id": session_id},
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Variant 2: deeply_nested_json
    # ------------------------------------------------------------------
    async def _test_deeply_nested_json(self, client) -> AttackResult:
        """POST deeply nested JSON (1000 levels) to the chat API.

        Deep recursion in JSON parsers can cause stack overflows.
        Expected: server should reject with 400/413/422.
        """
        # Build 1000-level nested object: {"a": {"a": {"a": ...}}}
        depth = 1000
        nested: dict = {"message": "end"}
        for _ in range(depth):
            nested = {"a": nested}

        payload = {
            "action": "send_message",
            "session_id": f"redteam-dos-nested-{uuid.uuid4().hex[:8]}",
            "data": nested,
        }

        start = time.monotonic()
        try:
            status_code, body, headers = await client.post(
                self._test_path,
                json_body=payload,
            )
            duration_ms = (time.monotonic() - start) * 1000
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            return self._make_result(
                variant="deeply_nested_json",
                status=Status.VULNERABLE,
                evidence=f"Exception after {duration_ms:.0f} ms: {exc}",
                details=(
                    f"Sent {depth}-level nested JSON. Client exception — server likely crashed "
                    "or the parser triggered a stack overflow."
                ),
                request={"nesting_depth": depth},
                response={"error": str(exc)},
                duration_ms=duration_ms,
            )

        duration_sec = duration_ms / 1000.0

        if status_code in (400, 413, 422):
            result_status = Status.DEFENDED
            details = (
                f"Server rejected {depth}-level nested JSON with {status_code}. "
                "Parser depth limiting is in place."
            )
        elif status_code == 500:
            result_status = Status.VULNERABLE
            details = (
                f"Server returned 500 for {depth}-level nested JSON. "
                "Possible stack overflow or unhandled parser error."
            )
        elif duration_sec > EXCESSIVE_TIMEOUT_SEC:
            result_status = Status.VULNERABLE
            details = (
                f"Server accepted {depth}-level nested JSON and took {duration_sec:.1f} s. "
                "Parser likely consumed excessive CPU/memory without depth limit."
            )
        elif status_code == 200:
            result_status = Status.PARTIAL
            details = (
                f"Server accepted {depth}-level nested JSON (status 200, {duration_sec:.1f} s). "
                "No parser depth limit detected."
            )
        else:
            result_status = Status.PARTIAL
            details = (
                f"Unexpected status {status_code} for deeply nested JSON after {duration_sec:.1f} s."
            )

        return self._make_result(
            variant="deeply_nested_json",
            status=result_status,
            evidence=f"Status: {status_code}, duration: {duration_sec:.2f} s, body: {body[:200]}",
            details=details,
            request={"nesting_depth": depth},
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Variant 3: many_fields_json
    # ------------------------------------------------------------------
    async def _test_many_fields_json(self, client) -> AttackResult:
        """POST JSON with 10 000 keys to test memory handling.

        Many parsers allocate per-key memory; a huge flat object can
        exhaust heap space or trigger hash-collision DoS.
        Expected: server should reject with 400/413 or handle gracefully.
        """
        num_keys = 10_000
        big_payload: dict = {f"field_{i}": f"value_{i}" for i in range(num_keys)}
        big_payload["action"] = "send_message"
        big_payload["session_id"] = f"redteam-dos-manyfields-{uuid.uuid4().hex[:8]}"
        big_payload["message"] = "ping"

        start = time.monotonic()
        try:
            status_code, body, headers = await client.post(
                self._test_path,
                json_body=big_payload,
            )
            duration_ms = (time.monotonic() - start) * 1000
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            return self._make_result(
                variant="many_fields_json",
                status=Status.VULNERABLE,
                evidence=f"Exception after {duration_ms:.0f} ms: {exc}",
                details=(
                    f"Sent JSON with {num_keys} keys. Client exception — server likely ran out "
                    "of memory or the connection was reset."
                ),
                request={"num_keys": num_keys},
                response={"error": str(exc)},
                duration_ms=duration_ms,
            )

        duration_sec = duration_ms / 1000.0

        if status_code in (400, 413, 422):
            result_status = Status.DEFENDED
            details = (
                f"Server rejected JSON with {num_keys} keys with {status_code}. "
                "Key-count or payload-size limit is enforced."
            )
        elif status_code == 500:
            result_status = Status.VULNERABLE
            details = (
                f"Server returned 500 for JSON with {num_keys} keys after {duration_sec:.1f} s. "
                "Possible memory exhaustion."
            )
        elif duration_sec > EXCESSIVE_TIMEOUT_SEC:
            result_status = Status.VULNERABLE
            details = (
                f"Server accepted JSON with {num_keys} keys and took {duration_sec:.1f} s. "
                "Excessive processing time suggests no key-count limit."
            )
        elif status_code == 200:
            result_status = Status.PARTIAL
            details = (
                f"Server accepted JSON with {num_keys} keys (status 200, {duration_sec:.1f} s). "
                "No key-count or payload-size limit detected."
            )
        else:
            result_status = Status.PARTIAL
            details = (
                f"Unexpected status {status_code} for many-fields JSON after {duration_sec:.1f} s."
            )

        return self._make_result(
            variant="many_fields_json",
            status=result_status,
            evidence=f"Status: {status_code}, duration: {duration_sec:.2f} s, body: {body[:200]}",
            details=details,
            request={"num_keys": num_keys},
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Variant 4: repeated_special_chars
    # ------------------------------------------------------------------
    async def _test_repeated_special_chars(self, client) -> AttackResult:
        """Send a message packed with unicode, emoji, and control characters.

        These stress string encoding, regex processing, and DB storage.
        Expected: server should handle or reject gracefully (not crash).
        PARTIAL: accepts without validation (no length/char filtering).
        VULNERABLE: server crashes or hangs.
        """
        session_id = f"redteam-dos-special-{uuid.uuid4().hex[:8]}"

        # Mix of multi-byte unicode, emoji, RTL, and C0/C1 control chars
        # Kept to ~4 KB so as not to overlap with the long_prompt test
        chunk = (
            "\U0001F4A5"   # explosion emoji (4 bytes UTF-8)
            "\u202e"       # RTL override
            "\u0000"       # null byte
            "\u007f"       # DEL
            "\u0085"       # NEXT LINE (C1 control)
            "\ufffe"       # reversed BOM
            "\ud800"       # lone surrogate (invalid in most encodings)
            "\u200b"       # zero-width space
            "الَّذِينَ"    # Arabic with combining diacritics
            "日本語テスト"  # CJK
            "🔥💀⚡🎯🚀"  # emoji cluster
        )
        message = chunk * 200  # ~4 KB of problematic characters

        start = time.monotonic()
        try:
            status_code, body, headers = await client.post(
                self._test_path,
                json_body={
                    "action": "send_message",
                    "message": message,
                    "session_id": session_id,
                },
            )
            duration_ms = (time.monotonic() - start) * 1000
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            return self._make_result(
                variant="repeated_special_chars",
                status=Status.VULNERABLE,
                evidence=f"Exception after {duration_ms:.0f} ms: {exc}",
                details=(
                    "Sent message with repeated unicode/emoji/control characters. "
                    "Client exception — server likely crashed during encoding or DB storage."
                ),
                request={"message_size": len(message), "session_id": session_id},
                response={"error": str(exc)},
                duration_ms=duration_ms,
            )

        duration_sec = duration_ms / 1000.0

        if status_code in (400, 422):
            result_status = Status.DEFENDED
            details = (
                f"Server rejected message with special characters with {status_code}. "
                "Character validation is enforced."
            )
        elif status_code == 500:
            result_status = Status.VULNERABLE
            details = (
                f"Server returned 500 for message with unicode/emoji/control chars after "
                f"{duration_sec:.1f} s. Possible encoding error or DB storage failure."
            )
        elif duration_sec > EXCESSIVE_TIMEOUT_SEC:
            result_status = Status.VULNERABLE
            details = (
                f"Server accepted special-char message but took {duration_sec:.1f} s. "
                "Possible runaway regex or encoding loop."
            )
        elif status_code == 200:
            result_status = Status.PARTIAL
            details = (
                f"Server accepted message with unicode/emoji/control characters "
                f"(status 200, {duration_sec:.1f} s). No character filtering detected — "
                "these chars may cause issues in downstream processing or DB storage."
            )
        else:
            result_status = Status.PARTIAL
            details = (
                f"Unexpected status {status_code} for special-char message after {duration_sec:.1f} s."
            )

        return self._make_result(
            variant="repeated_special_chars",
            status=result_status,
            severity=Severity.LOW,
            evidence=f"Status: {status_code}, duration: {duration_sec:.2f} s, body: {body[:200]}",
            details=details,
            request={
                "message_size": f"{len(message)} chars",
                "char_types": "emoji, RTL, null byte, DEL, C1 control, BOM, Arabic, CJK",
                "session_id": session_id,
            },
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Variant 5: rapid_fire_chat
    # ------------------------------------------------------------------
    async def _test_rapid_fire_chat(self, client) -> AttackResult:
        """Fire 20 chat messages concurrently (not waiting for each response).

        Tests whether the server queues, rate-limits, or falls over under
        sudden concurrent chat load directed at the Ollama backend.
        DEFENDED: server rate-limits (429) or queues gracefully.
        PARTIAL: all accepted but response times are very high.
        VULNERABLE: 500 errors or connection failures indicating exhaustion.
        """
        num_requests = 20
        base_session = f"redteam-dos-rapid-{uuid.uuid4().hex[:8]}"

        async def _fire(idx: int) -> tuple[int, float, str]:
            """Send one chat message, return (status_code, duration_ms, body_snippet)."""
            s_id = f"{base_session}-{idx}"
            t0 = time.monotonic()
            try:
                status_code, body, _headers = await client.post(
                    self._test_path,
                    json_body={
                        "action": "send_message",
                        "message": f"Rapid fire test message {idx}",
                        "session_id": s_id,
                    },
                )
                return status_code, (time.monotonic() - t0) * 1000, body[:100]
            except Exception as exc:
                return 0, (time.monotonic() - t0) * 1000, str(exc)

        wall_start = time.monotonic()
        tasks = [_fire(i) for i in range(num_requests)]
        fire_results = await asyncio.gather(*tasks)
        wall_elapsed_ms = (time.monotonic() - wall_start) * 1000

        statuses = [r[0] for r in fire_results]
        durations = [r[1] for r in fire_results]

        count_429 = statuses.count(429)
        count_500 = statuses.count(500)
        count_200 = statuses.count(200)
        count_error = statuses.count(0)  # connection-level failure
        count_ok = count_200 + count_429  # 429 = rate limited but alive
        avg_duration_ms = sum(durations) / len(durations)
        max_duration_ms = max(durations)

        status_dist = {str(s): statuses.count(s) for s in set(statuses)}

        if count_429 > 0:
            result_status = Status.DEFENDED
            details = (
                f"Server rate-limited {count_429}/{num_requests} concurrent requests "
                f"(429). Queue/rate-limit protection is active. "
                f"Wall time: {wall_elapsed_ms:.0f} ms, avg latency: {avg_duration_ms:.0f} ms."
            )
        elif count_500 > 0 or count_error > 0:
            result_status = Status.VULNERABLE
            details = (
                f"{count_500} server errors and {count_error} connection failures out of "
                f"{num_requests} concurrent requests. Server may be overwhelmed by "
                f"concurrent Ollama dispatches. "
                f"Wall time: {wall_elapsed_ms:.0f} ms."
            )
        elif max_duration_ms > EXCESSIVE_TIMEOUT_SEC * 1000:
            result_status = Status.PARTIAL
            details = (
                f"All {num_requests} requests accepted (status 200) but max latency was "
                f"{max_duration_ms / 1000:.1f} s — exceeds {EXCESSIVE_TIMEOUT_SEC} s threshold. "
                "No rate limiting detected; Ollama may be serially queuing."
            )
        elif count_200 == num_requests:
            result_status = Status.PARTIAL
            details = (
                f"All {num_requests} rapid-fire requests returned 200 in {wall_elapsed_ms:.0f} ms "
                f"(avg latency: {avg_duration_ms:.0f} ms, max: {max_duration_ms:.0f} ms). "
                "No rate limiting or concurrency throttling detected."
            )
        else:
            result_status = Status.PARTIAL
            details = (
                f"Mixed responses to {num_requests} concurrent requests. "
                f"Status distribution: {status_dist}. "
                f"Wall time: {wall_elapsed_ms:.0f} ms."
            )

        return self._make_result(
            variant="rapid_fire_chat",
            status=result_status,
            evidence=(
                f"Fired {num_requests} concurrent requests in {wall_elapsed_ms:.0f} ms. "
                f"Status distribution: {status_dist}. "
                f"Avg latency: {avg_duration_ms:.0f} ms, max: {max_duration_ms:.0f} ms."
            ),
            details=details,
            request={
                "num_requests": num_requests,
                "strategy": "asyncio.gather (all concurrent)",
                "base_session": base_session,
            },
            response={
                "status_distribution": status_dist,
                "wall_elapsed_ms": round(wall_elapsed_ms),
                "avg_latency_ms": round(avg_duration_ms),
                "max_latency_ms": round(max_duration_ms),
            },
            duration_ms=wall_elapsed_ms,
        )
