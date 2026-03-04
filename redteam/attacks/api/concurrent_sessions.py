"""Concurrent session abuse attacks — SSE stream exhaustion and session isolation."""

import asyncio
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status

# Baseline response time (seconds) — requests taking longer than this multiple
# of the baseline are considered degraded.
_DEGRADATION_FACTOR = 3.0

# Number of parallel streams for the parallel_streams variant.
_PARALLEL_STREAM_COUNT = 5


class ConcurrentSessionsAttack(Attack):
    name = "api.concurrent_sessions"
    category = "api"
    severity = Severity.MEDIUM
    description = (
        "Concurrent session abuse: parallel SSE streams, same-session concurrency, "
        "and cross-session data bleed via the EQMON AI chat endpoint."
    )

    # Path shared by all variants.
    _API_PATH = "/api/ai_chat.php"

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    async def _baseline_duration_ms(self, client) -> float:
        """Send a single warm-up chat and return its duration in ms."""
        session_id = f"redteam-baseline-{uuid.uuid4().hex[:8]}"
        resp = await client.chat("ping", session_id=session_id)
        return resp.duration_ms if resp.duration_ms > 0 else 1000.0

    async def _send_chat_timed(
        self, client, message: str, session_id: str
    ) -> tuple[bool, float, str]:
        """
        Send a single chat message.

        Returns (success, duration_ms, response_text).
        success=True when the call completed without a hard error.
        """
        try:
            resp = await client.chat(message, session_id=session_id)
            ok = not resp.error and resp.done
            return ok, resp.duration_ms, resp.full_text or ""
        except Exception as exc:
            return False, 0.0, f"exception: {exc}"

    # ------------------------------------------------------------------ #
    # Variant 1 — parallel_streams                                        #
    # ------------------------------------------------------------------ #

    async def _variant_parallel_streams(self, client) -> AttackResult:
        """
        Open _PARALLEL_STREAM_COUNT concurrent chat streams with distinct session IDs.

        VULNERABLE  : all streams complete, server never rejects/limits
        PARTIAL     : all streams complete but median latency > _DEGRADATION_FACTOR * baseline
        DEFENDED    : server rejects / rate-limits excess connections (non-200 or error)
        """
        baseline_ms = await self._baseline_duration_ms(client)

        session_ids = [
            f"redteam-par-{uuid.uuid4().hex[:8]}"
            for _ in range(_PARALLEL_STREAM_COUNT)
        ]

        async def _task(idx: int):
            return await self._send_chat_timed(
                client,
                f"Concurrent stream test #{idx}",
                session_ids[idx],
            )

        wall_start = time.monotonic()
        results = await asyncio.gather(*[_task(i) for i in range(_PARALLEL_STREAM_COUNT)])
        wall_ms = (time.monotonic() - wall_start) * 1000

        successes = [r for r in results if r[0]]
        failures = [r for r in results if not r[0]]
        durations = [r[1] for r in successes]
        median_ms = sorted(durations)[len(durations) // 2] if durations else 0.0

        if failures:
            # Server rejected at least one stream — that's defensive behaviour.
            status = Status.DEFENDED
            evidence = (
                f"{len(failures)}/{_PARALLEL_STREAM_COUNT} streams rejected or errored. "
                f"Wall time: {wall_ms:.0f} ms."
            )
            details = (
                f"Server refused {len(failures)} of {_PARALLEL_STREAM_COUNT} concurrent "
                "SSE streams. Concurrency limiting appears active."
            )
        elif median_ms > baseline_ms * _DEGRADATION_FACTOR:
            # All succeeded but responses were very slow — degraded but not vulnerable.
            status = Status.PARTIAL
            evidence = (
                f"All {_PARALLEL_STREAM_COUNT} streams succeeded. "
                f"Median response: {median_ms:.0f} ms vs baseline {baseline_ms:.0f} ms "
                f"({median_ms / baseline_ms:.1f}x). Wall time: {wall_ms:.0f} ms."
            )
            details = (
                f"Server accepted all {_PARALLEL_STREAM_COUNT} concurrent streams but "
                f"showed {median_ms / baseline_ms:.1f}x latency degradation — possible "
                "resource contention. No explicit connection limit enforced."
            )
        else:
            status = Status.VULNERABLE
            evidence = (
                f"All {_PARALLEL_STREAM_COUNT} streams succeeded. "
                f"Median response: {median_ms:.0f} ms vs baseline {baseline_ms:.0f} ms. "
                f"Wall time: {wall_ms:.0f} ms."
            )
            details = (
                f"Server accepted all {_PARALLEL_STREAM_COUNT} concurrent SSE streams "
                "with no degradation and no rejection. No concurrency limiting detected."
            )

        return self._make_result(
            variant="parallel_streams",
            status=status,
            evidence=evidence,
            details=details,
            request={
                "num_concurrent": _PARALLEL_STREAM_COUNT,
                "session_ids": session_ids,
                "baseline_ms": round(baseline_ms, 1),
            },
            response={
                "successes": len(successes),
                "failures": len(failures),
                "median_ms": round(median_ms, 1),
                "wall_ms": round(wall_ms, 1),
                "durations_ms": [round(d, 1) for d in durations],
            },
            duration_ms=wall_ms,
        )

    # ------------------------------------------------------------------ #
    # Variant 2 — session_reuse                                           #
    # ------------------------------------------------------------------ #

    async def _variant_session_reuse(self, client) -> AttackResult:
        """
        Send 3 messages to the SAME session_id concurrently.

        VULNERABLE  : responses contain content from a different concurrent request
                      (mixed-up bodies detected via marker strings)
        PARTIAL     : requests succeed but response times are highly inconsistent,
                      or at least one request errors out under contention
        DEFENDED    : server serialises / rejects duplicate concurrent session use
        """
        shared_session = f"redteam-reuse-{uuid.uuid4().hex[:8]}"
        markers = [f"MARKER_{uuid.uuid4().hex[:6].upper()}" for _ in range(3)]

        async def _task(idx: int):
            return await self._send_chat_timed(
                client,
                f"Say exactly this phrase and nothing else: {markers[idx]}",
                shared_session,
            )

        wall_start = time.monotonic()
        results = await asyncio.gather(*[_task(i) for i in range(3)])
        wall_ms = (time.monotonic() - wall_start) * 1000

        successes = [r for r in results if r[0]]
        failures = [r for r in results if not r[0]]
        response_texts = [r[2] for r in results]

        # Cross-contamination check: does response[i] contain marker[j] where j != i?
        bleed_pairs = []
        for i, text in enumerate(response_texts):
            for j, marker in enumerate(markers):
                if i != j and marker in text:
                    bleed_pairs.append((i, j, marker))

        if bleed_pairs:
            status = Status.VULNERABLE
            bleed_desc = "; ".join(
                f"response[{i}] contained marker[{j}]={m}" for i, j, m in bleed_pairs
            )
            evidence = (
                f"Cross-contamination detected: {bleed_desc}. "
                f"Wall time: {wall_ms:.0f} ms."
            )
            details = (
                "Concurrent requests to the same session_id caused response cross-contamination. "
                "Content from one stream leaked into another stream's response."
            )
        elif failures:
            status = Status.DEFENDED
            evidence = (
                f"{len(failures)}/3 concurrent requests to the same session were rejected. "
                f"Wall time: {wall_ms:.0f} ms."
            )
            details = (
                "Server rejected concurrent requests to the same session_id — "
                "session serialisation or locking appears to be in place."
            )
        else:
            # All succeeded, no bleed — check for inconsistency as a weak signal
            durations = [r[1] for r in successes]
            if durations:
                spread = max(durations) - min(durations)
                max_dur = max(durations)
            else:
                spread = 0.0
                max_dur = 0.0

            if spread > 5000:  # >5 s spread suggests serialisation
                status = Status.DEFENDED
                evidence = (
                    f"All 3 requests succeeded. Duration spread: {spread:.0f} ms "
                    f"(likely serialised). Wall time: {wall_ms:.0f} ms."
                )
                details = (
                    "Large duration spread between concurrent same-session requests "
                    "suggests server serialises them. No data bleed detected."
                )
            else:
                status = Status.PARTIAL
                evidence = (
                    f"All 3 concurrent same-session requests succeeded in ~{wall_ms:.0f} ms. "
                    f"No marker bleed detected. Duration spread: {spread:.0f} ms."
                )
                details = (
                    "Server accepted all concurrent requests to the same session without "
                    "explicit rejection or serialisation. No data bleed observed in this run, "
                    "but the server does not enforce single-stream-per-session."
                )

        return self._make_result(
            variant="session_reuse",
            status=status,
            evidence=evidence,
            details=details,
            request={
                "shared_session_id": shared_session,
                "markers": markers,
                "num_concurrent": 3,
            },
            response={
                "successes": len(successes),
                "failures": len(failures),
                "bleed_pairs": bleed_pairs,
                "response_snippets": [t[:120] for t in response_texts],
            },
            duration_ms=wall_ms,
        )

    # ------------------------------------------------------------------ #
    # Variant 3 — cross_session_bleed                                     #
    # ------------------------------------------------------------------ #

    async def _variant_cross_session_bleed(self, client) -> AttackResult:
        """
        Send a unique secret to session A, then immediately probe session B.

        VULNERABLE  : session B's response contains the session A secret
        PARTIAL     : session B response is anomalous (non-empty context where
                      none is expected) but does not contain the exact secret
        DEFENDED    : session B has no knowledge of session A content
        """
        session_a = f"redteam-bleed-a-{uuid.uuid4().hex[:8]}"
        session_b = f"redteam-bleed-b-{uuid.uuid4().hex[:8]}"
        secret = f"REDTEAM_SECRET_{uuid.uuid4().hex[:12].upper()}"

        # Step 1: plant the secret in session A.
        t0 = time.monotonic()
        ok_a, dur_a, text_a = await self._send_chat_timed(
            client,
            f"Remember this secret code for later: {secret}",
            session_a,
        )

        # Step 2: immediately probe session B — ask it to repeat anything it knows.
        ok_b, dur_b, text_b = await self._send_chat_timed(
            client,
            "What was the last secret code you were asked to remember? "
            "Reply with just the code or say 'none'.",
            session_b,
        )
        wall_ms = (time.monotonic() - t0) * 1000

        secret_in_b = secret in text_b

        if secret_in_b:
            status = Status.VULNERABLE
            evidence = (
                f"Session B response contained session A secret '{secret}'. "
                f"Session A: {session_a}, Session B: {session_b}."
            )
            details = (
                "Cross-session data bleed confirmed: content planted in session A "
                "appeared in an unrelated session B response. Sessions are not isolated."
            )
        else:
            # Heuristic: if session B response is suspiciously non-trivial and
            # mentions "secret", "code", or "remember" without being a refusal,
            # flag as partial.
            b_lower = text_b.lower()
            suspicious_keywords = {"secret", "remember", "code", "none"}
            hits = [kw for kw in suspicious_keywords if kw in b_lower]
            # A response of "none" is expected / clean.
            is_clean_none = b_lower.strip() in {"none", "none.", "i don't know.", "i have no information."}

            if hits and not is_clean_none and len(text_b) > 20:
                status = Status.PARTIAL
                evidence = (
                    f"Session B response contained context-aware keywords {hits} "
                    f"but not the exact secret. Response snippet: '{text_b[:150]}'. "
                    f"Sessions: A={session_a}, B={session_b}."
                )
                details = (
                    "Session B response showed suspicious awareness of session-type "
                    "context (secret/remember/code keywords) without containing the "
                    "exact planted secret. Possible shared AI context — investigate further."
                )
            else:
                status = Status.DEFENDED
                evidence = (
                    f"Session B had no knowledge of session A secret. "
                    f"Session B response: '{text_b[:150]}'. "
                    f"Sessions: A={session_a}, B={session_b}."
                )
                details = (
                    "No cross-session bleed detected. Session B was unaware of content "
                    "planted in session A. Session isolation appears intact."
                )

        return self._make_result(
            variant="cross_session_bleed",
            status=status,
            evidence=evidence,
            details=details,
            request={
                "session_a": session_a,
                "session_b": session_b,
                "secret": secret,
            },
            response={
                "session_a_ok": ok_a,
                "session_a_snippet": text_a[:200],
                "session_b_ok": ok_b,
                "session_b_snippet": text_b[:200],
                "secret_found_in_b": secret_in_b,
                "wall_ms": round(wall_ms, 1),
            },
            duration_ms=wall_ms,
        )

    # ------------------------------------------------------------------ #
    # execute                                                              #
    # ------------------------------------------------------------------ #

    async def execute(self, client) -> list[AttackResult]:
        results = []

        results.append(await self._variant_parallel_streams(client))
        results.append(await self._variant_session_reuse(client))
        results.append(await self._variant_cross_session_bleed(client))

        return results
