"""Base collector interface."""
from abc import ABC, abstractmethod
from blueteam.models import SecurityEvent


class BaseCollector(ABC):
    """Abstract base for all event collectors."""

    def __init__(self, config: dict):
        self.config = config
        self._last_position = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Collector identifier."""
        ...

    @abstractmethod
    def collect(self) -> list[SecurityEvent]:
        """Collect new events since last poll. Returns list of SecurityEvent."""
        ...

    def is_enabled(self) -> bool:
        """Check if this collector is enabled in config."""
        collectors = self.config.get("collectors", {})
        return collectors.get(self.name, {}).get("enabled", False)
