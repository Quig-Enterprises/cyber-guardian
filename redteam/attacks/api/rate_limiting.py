"""Rate limiting attacks - flood testing against API endpoints."""

import asyncio
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class RateLimitingAttack(Attack):
    name = "api.rate_limiting"
    category = "api"
    severity = Severity.MEDIUM
    description = "Rate limiting and flood protection tests"
    target_types = {"eqmon", "wordpress", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = self._get_test_endpoints()[0]

        # Pull throttle overrides for this attack (non-empty only in AWS mode)
        throttle = self._get_throttle("api.rate_limiting")

        # 1. Rapid-fire GET requests (default 50; reduced to 10 in AWS mode)
        session_id = f"redteam-ratelimit-{uuid.uuid4().hex[:8]}"
        num_requests = throttle.get("serial_requests", 50)
        delay_ms = throttle.get("delay_ms", 0)
        start = time.monotonic()
        statuses = []

        for i in range(num_requests):
            status_code, body, headers = await client.get(
                test_path,
                params={"session_id": f"{session_id}-{i}"},
            )
            statuses.append(status_code)
            if delay_ms:
                await asyncio.sleep(delay_ms / 1000.0)

        elapsed = time.monotonic() - start
        rate_limited = any(s == 429 for s in statuses)
        all_succeeded = all(s in (200, 204, 404) for s in statuses)

        if rate_limited:
            rl_status = Status.DEFENDED
            first_429 = statuses.index(429)
            detail = f"Rate limited after {first_429} requests. First 429 at request #{first_429 + 1}."
        elif all_succeeded:
            rl_status = Status.VULNERABLE
            detail = f"All {num_requests} rapid requests succeeded in {elapsed:.1f}s. No rate limiting detected."
        else:
            rl_status = Status.PARTIAL
            detail = f"Mixed responses (no 429). Statuses: {set(statuses)}."
        results.append(self._make_result(
            variant=f"rapid_fire_{num_requests}_gets",
            status=rl_status,
            evidence=(
                f"Sent {num_requests} requests in {elapsed:.1f}s. "
                f"429 count: {statuses.count(429)}, "
                f"200 count: {statuses.count(200)}"
            ),
            details=detail,
            request={"num_requests": num_requests, "elapsed_sec": round(elapsed, 2)},
            response={"status_distribution": {str(s): statuses.count(s) for s in set(statuses)}},
        ))

        # 2. Concurrent SSE streams (default 10; reduced to 2 in AWS mode)
        # Opening many concurrent SSE streams can exhaust server resources.
        num_concurrent = throttle.get("concurrent_streams", 10)

        async def _send_chat(idx: int) -> tuple[int, float]:
            """Send a chat request and return (status_code, duration_ms)."""
            s_id = f"redteam-concurrent-{uuid.uuid4().hex[:8]}"
            req_start = time.monotonic()
            try:
                status_code, body, headers = await client.post(
                    test_path,
                    json_body={
                        "action": "send_message",
                        "message": f"Concurrent test #{idx}",
                        "session_id": s_id,
                    },
                )
                duration = (time.monotonic() - req_start) * 1000
                return status_code, duration
            except Exception:
                duration = (time.monotonic() - req_start) * 1000
                return 0, duration

        start = time.monotonic()
        tasks = [_send_chat(i) for i in range(num_concurrent)]
        concurrent_results = await asyncio.gather(*tasks)
        elapsed = time.monotonic() - start

        concurrent_statuses = [r[0] for r in concurrent_results]
        rate_limited = any(s == 429 for s in concurrent_statuses)
        all_succeeded = all(s in (200, 204) for s in concurrent_statuses)
        errors = sum(1 for s in concurrent_statuses if s >= 500 or s == 0)

        if rate_limited:
            rl_status = Status.DEFENDED
            detail = f"Rate limited under concurrent load. 429 count: {concurrent_statuses.count(429)}."
        elif all_succeeded:
            rl_status = Status.VULNERABLE
            detail = (
                f"All {num_concurrent} concurrent SSE streams accepted in {elapsed:.1f}s. "
                "No concurrency limiting detected."
            )
        elif errors > 0:
            rl_status = Status.PARTIAL
            detail = (
                f"{errors} errors under concurrent load. "
                "Server may be overwhelmed but doesn't explicitly rate limit."
            )
        else:
            rl_status = Status.PARTIAL
            detail = f"Mixed responses under concurrent load. Statuses: {set(concurrent_statuses)}."
        results.append(self._make_result(
            variant=f"concurrent_sse_{num_concurrent}_streams",
            status=rl_status,
            evidence=(
                f"Sent {num_concurrent} concurrent requests in {elapsed:.1f}s. "
                f"Statuses: {concurrent_statuses}"
            ),
            details=detail,
            request={"num_concurrent": num_concurrent, "elapsed_sec": round(elapsed, 2)},
            response={
                "status_distribution": {
                    str(s): concurrent_statuses.count(s) for s in set(concurrent_statuses)
                },
            },
        ))

        # 3. Note spam (default 100; reduced to 10 in AWS mode)
        num_notes = throttle.get("note_count", 100)
        device_id = f"redteam-ratelimit-device-{uuid.uuid4().hex[:8]}"
        start = time.monotonic()
        note_statuses = []
        created_note_ids = []

        for i in range(num_notes):
            status_code, body, headers = await client.post(
                test_path,
                json_body={
                    "action": "add_note",
                    "device_id": device_id,
                    "note": f"REDTEAM-SPAM-NOTE-{i:04d}",
                },
            )
            note_statuses.append(status_code)
            # Track created note IDs for cleanup
            if status_code == 200 and '"id"' in body:
                try:
                    import json
                    resp_data = json.loads(body)
                    if "id" in resp_data:
                        created_note_ids.append(resp_data["id"])
                except Exception:
                    pass

        elapsed = time.monotonic() - start
        rate_limited = any(s == 429 for s in note_statuses)
        all_succeeded = all(s in (200, 201) for s in note_statuses)

        if rate_limited:
            rl_status = Status.DEFENDED
            first_429 = note_statuses.index(429)
            detail = f"Rate limited after {first_429} notes. First 429 at note #{first_429 + 1}."
        elif all_succeeded:
            rl_status = Status.VULNERABLE
            detail = (
                f"All {num_notes} notes created in {elapsed:.1f}s "
                f"({num_notes / elapsed:.1f} notes/sec). No rate limiting."
            )
        else:
            rl_status = Status.PARTIAL
            detail = f"Mixed responses during note spam. Statuses: {set(note_statuses)}."
        results.append(self._make_result(
            variant=f"note_spam_{num_notes}",
            status=rl_status,
            evidence=(
                f"Created {note_statuses.count(200)} of {num_notes} notes in {elapsed:.1f}s. "
                f"429 count: {note_statuses.count(429)}"
            ),
            details=detail,
            request={
                "num_notes": num_notes,
                "device_id": device_id,
                "elapsed_sec": round(elapsed, 2),
            },
            response={"status_distribution": {str(s): note_statuses.count(s) for s in set(note_statuses)}},
        ))

        # Store cleanup data for later
        self._cleanup_device_id = device_id
        self._cleanup_note_ids = created_note_ids

        return results

    async def cleanup(self, client) -> None:
        """Delete spam notes created during rate limiting tests."""
        test_path = self._get_test_endpoints()[0]
        for note_id in getattr(self, "_cleanup_note_ids", []):
            try:
                await client.delete(
                    test_path,
                    params={"action": "delete_note", "id": str(note_id)},
                )
            except Exception:
                pass
