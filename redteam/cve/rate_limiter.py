"""Async token-bucket rate limiter for CVE data sources."""

import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token-bucket rate limiter with optional AWS mode throttling.

    Args:
        name: Identifier for this limiter (e.g. source name).
        max_requests: Maximum tokens in the bucket.
        window_seconds: Time window for full token refill.
        aws_mode: If True, halve max_requests for conservative throttling.
    """

    def __init__(
        self,
        name: str,
        max_requests: int,
        window_seconds: float,
        aws_mode: bool = False,
    ):
        self.name = name
        self._max_tokens = max_requests // 2 if aws_mode else max_requests
        if self._max_tokens < 1:
            self._max_tokens = 1
        self._window = window_seconds
        self._tokens = float(self._max_tokens)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._refill_rate = self._max_tokens / self._window  # tokens per second

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate wait time for next token
                wait_time = (1.0 - self._tokens) / self._refill_rate

            logger.debug(
                "RateLimiter[%s]: throttling for %.2fs", self.name, wait_time
            )
            await asyncio.sleep(wait_time)

    def _refill(self) -> None:
        """Refill tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        new_tokens = elapsed * self._refill_rate
        self._tokens = min(float(self._max_tokens), self._tokens + new_tokens)
        self._last_refill = now
