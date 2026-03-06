"""Base classes for the security red team framework."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    VULNERABLE = "vulnerable"
    PARTIAL = "partial"
    DEFENDED = "defended"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class AttackResult:
    """Result of a single attack variant."""
    attack_name: str
    variant: str
    status: Status
    severity: Severity
    evidence: str = ""
    details: str = ""
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    duration_ms: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return self.status in (Status.VULNERABLE, Status.PARTIAL)


@dataclass
class Score:
    """Aggregated score for an attack module."""
    attack_name: str
    category: str
    total_variants: int = 0
    vulnerable: int = 0
    partial: int = 0
    defended: int = 0
    errors: int = 0
    worst_severity: Severity = Severity.INFO
    results: list[AttackResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def pass_rate(self) -> float:
        if self.total_variants == 0:
            return 0.0
        return self.defended / self.total_variants

    @property
    def has_findings(self) -> bool:
        return self.vulnerable > 0 or self.partial > 0


class Attack(ABC):
    """Base class for all attack modules."""
    name: str = "unnamed"
    category: str = "unknown"
    severity: Severity = Severity.INFO
    description: str = ""
    target_types: set[str] = {"eqmon"}

    # Set by runner before execute() is called.
    _config: dict = {}

    def _is_aws_mode(self) -> bool:
        """Return True when running in AWS-safe mode."""
        return self._config.get("execution", {}).get("mode", "full") == "aws"

    def _get_throttle(self, attack_key: str) -> dict:
        """Return throttle overrides for this attack in AWS mode, or {} in full mode."""
        if not self._is_aws_mode():
            return {}
        return self._config.get("execution", {}).get("aws", {}).get("throttle", {}).get(attack_key, {})

    def _get_blocked_ips(self) -> list:
        """Return IPs that must never appear in attack payloads (AWS mode only)."""
        if not self._is_aws_mode():
            return []
        return self._config.get("execution", {}).get("aws", {}).get("blocked_ips", [])

    @abstractmethod
    async def execute(self, client) -> list[AttackResult]:
        """Run all variants of this attack. Returns a list of results."""
        ...

    async def cleanup(self, client) -> None:
        """Optional: clean up any test artifacts created by this attack."""
        pass

    def score(self, results: list[AttackResult]) -> Score:
        """Aggregate individual results into a Score."""
        score = Score(
            attack_name=self.name,
            category=self.category,
            total_variants=len(results),
            results=results,
        )
        severity_order = list(Severity)
        for r in results:
            if r.status == Status.VULNERABLE:
                score.vulnerable += 1
            elif r.status == Status.PARTIAL:
                score.partial += 1
            elif r.status == Status.DEFENDED:
                score.defended += 1
            elif r.status == Status.ERROR:
                score.errors += 1
            if r.is_vulnerable and severity_order.index(r.severity) < severity_order.index(score.worst_severity):
                score.worst_severity = r.severity
        return score

    def _make_result(self, variant: str, status: Status, severity: Severity = None,
                     evidence: str = "", details: str = "",
                     request: dict = None, response: dict = None,
                     duration_ms: float = 0.0) -> AttackResult:
        """Helper to create an AttackResult with defaults from this attack."""
        return AttackResult(
            attack_name=self.name,
            variant=variant,
            status=status,
            severity=severity or self.severity,
            evidence=evidence,
            details=details,
            request=request or {},
            response=response or {},
            duration_ms=duration_ms,
        )
