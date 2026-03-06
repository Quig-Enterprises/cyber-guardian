"""Correlation engine — buffers events and runs detection rules."""
from collections import deque
from datetime import datetime, timezone, timedelta
from blueteam.models import SecurityEvent, SecurityIncident


class CorrelationEngine:
    """Processes security events through correlation rules."""

    def __init__(self, config: dict):
        self.config = config
        window = config.get("correlation", {}).get("window_seconds", 300)
        self._window = timedelta(seconds=window)
        self._buffer: deque[SecurityEvent] = deque()
        self._rules: list = []

    def register_rule(self, rule):
        """Register a correlation rule."""
        self._rules.append(rule)

    def process_events(self, events: list[SecurityEvent]) -> list[SecurityIncident]:
        """Add events to buffer and run all rules."""
        now = datetime.now(timezone.utc)
        cutoff = now - self._window

        # Add new events
        for event in events:
            self._buffer.append(event)

        # Prune expired events
        while self._buffer and self._buffer[0].timestamp < cutoff:
            self._buffer.popleft()

        # Run rules
        incidents = []
        buffer_list = list(self._buffer)
        for rule in self._rules:
            result = rule.evaluate(buffer_list, self.config)
            if result:
                incidents.extend(result if isinstance(result, list) else [result])

        return incidents
