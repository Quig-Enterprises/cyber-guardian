# Task 02: Core Abstractions

This task creates the base classes for the attack framework. All code goes in `/opt/security-red-team/redteam/`.

## Files to create

- `redteam/base.py` - Attack base class, AttackResult, Score
- `redteam/scoring.py` - Severity enum, scoring aggregation
- `tests/test_scoring.py` - Unit tests

## redteam/base.py

```python
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
```

## redteam/scoring.py

```python
"""Scoring aggregation and report summary generation."""

from .base import Score, Severity, Status, AttackResult


def aggregate_scores(scores: list[Score]) -> dict:
    """Aggregate all scores into a summary report dict."""
    summary = {
        "total_attacks": len(scores),
        "total_variants": sum(s.total_variants for s in scores),
        "total_vulnerable": sum(s.vulnerable for s in scores),
        "total_partial": sum(s.partial for s in scores),
        "total_defended": sum(s.defended for s in scores),
        "total_errors": sum(s.errors for s in scores),
        "by_category": {},
        "by_severity": {sev.value: 0 for sev in Severity},
        "worst_severity": Severity.INFO,
        "scores": scores,
    }

    severity_order = list(Severity)

    for s in scores:
        # By category
        cat = s.category
        if cat not in summary["by_category"]:
            summary["by_category"][cat] = {
                "attacks": 0, "vulnerable": 0, "partial": 0, "defended": 0, "errors": 0
            }
        summary["by_category"][cat]["attacks"] += 1
        summary["by_category"][cat]["vulnerable"] += s.vulnerable
        summary["by_category"][cat]["partial"] += s.partial
        summary["by_category"][cat]["defended"] += s.defended
        summary["by_category"][cat]["errors"] += s.errors

        # By severity (count findings)
        for r in s.results:
            if r.is_vulnerable:
                summary["by_severity"][r.severity.value] += 1

        # Worst severity
        if s.has_findings and severity_order.index(s.worst_severity) < severity_order.index(summary["worst_severity"]):
            summary["worst_severity"] = s.worst_severity

    return summary


def severity_color(severity: Severity) -> str:
    """Return Rich color name for a severity level."""
    return {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }.get(severity, "white")


def status_color(status: Status) -> str:
    """Return Rich color name for a status."""
    return {
        Status.VULNERABLE: "red bold",
        Status.PARTIAL: "yellow",
        Status.DEFENDED: "green",
        Status.ERROR: "magenta",
        Status.SKIPPED: "dim",
    }.get(status, "white")
```

## tests/test_scoring.py

```python
"""Unit tests for core abstractions: AttackResult, Score, Attack, aggregate_scores."""

import pytest
from redteam.base import (
    Attack, AttackResult, Score, Severity, Status
)
from redteam.scoring import aggregate_scores


# ---------------------------------------------------------------------------
# Concrete Attack subclass for testing (cannot instantiate ABC directly)
# ---------------------------------------------------------------------------

class DummyAttack(Attack):
    name = "dummy"
    category = "test"
    severity = Severity.MEDIUM

    async def execute(self, client) -> list[AttackResult]:
        return []


# ---------------------------------------------------------------------------
# AttackResult.is_vulnerable
# ---------------------------------------------------------------------------

class TestAttackResultIsVulnerable:
    def _make(self, status: Status) -> AttackResult:
        return AttackResult(
            attack_name="test",
            variant="v1",
            status=status,
            severity=Severity.HIGH,
        )

    def test_vulnerable_status_is_vulnerable(self):
        assert self._make(Status.VULNERABLE).is_vulnerable is True

    def test_partial_status_is_vulnerable(self):
        assert self._make(Status.PARTIAL).is_vulnerable is True

    def test_defended_not_vulnerable(self):
        assert self._make(Status.DEFENDED).is_vulnerable is False

    def test_error_not_vulnerable(self):
        assert self._make(Status.ERROR).is_vulnerable is False

    def test_skipped_not_vulnerable(self):
        assert self._make(Status.SKIPPED).is_vulnerable is False


# ---------------------------------------------------------------------------
# Attack.score() counting
# ---------------------------------------------------------------------------

class TestAttackScore:
    def setup_method(self):
        self.attack = DummyAttack()

    def _make_result(self, status: Status, severity: Severity = Severity.MEDIUM) -> AttackResult:
        return AttackResult(
            attack_name="dummy",
            variant="v",
            status=status,
            severity=severity,
        )

    def test_empty_results(self):
        s = self.attack.score([])
        assert s.total_variants == 0
        assert s.vulnerable == 0
        assert s.partial == 0
        assert s.defended == 0
        assert s.errors == 0

    def test_counts_vulnerable(self):
        results = [
            self._make_result(Status.VULNERABLE),
            self._make_result(Status.VULNERABLE),
        ]
        s = self.attack.score(results)
        assert s.vulnerable == 2
        assert s.total_variants == 2

    def test_counts_partial(self):
        results = [self._make_result(Status.PARTIAL)]
        s = self.attack.score(results)
        assert s.partial == 1
        assert s.vulnerable == 0

    def test_counts_defended(self):
        results = [self._make_result(Status.DEFENDED)]
        s = self.attack.score(results)
        assert s.defended == 1

    def test_counts_errors(self):
        results = [self._make_result(Status.ERROR)]
        s = self.attack.score(results)
        assert s.errors == 1

    def test_mixed_counts(self):
        results = [
            self._make_result(Status.VULNERABLE),
            self._make_result(Status.PARTIAL),
            self._make_result(Status.DEFENDED),
            self._make_result(Status.ERROR),
            self._make_result(Status.SKIPPED),
        ]
        s = self.attack.score(results)
        assert s.total_variants == 5
        assert s.vulnerable == 1
        assert s.partial == 1
        assert s.defended == 1
        assert s.errors == 1

    def test_attack_name_and_category_preserved(self):
        s = self.attack.score([])
        assert s.attack_name == "dummy"
        assert s.category == "test"


# ---------------------------------------------------------------------------
# Attack.score() worst_severity
# ---------------------------------------------------------------------------

class TestAttackScoreWorstSeverity:
    def setup_method(self):
        self.attack = DummyAttack()

    def _vuln(self, severity: Severity) -> AttackResult:
        return AttackResult(
            attack_name="dummy", variant="v",
            status=Status.VULNERABLE, severity=severity,
        )

    def _defended(self, severity: Severity) -> AttackResult:
        return AttackResult(
            attack_name="dummy", variant="v",
            status=Status.DEFENDED, severity=severity,
        )

    def test_no_findings_worst_severity_is_info(self):
        results = [self._defended(Severity.CRITICAL)]
        s = self.attack.score(results)
        assert s.worst_severity == Severity.INFO

    def test_single_vulnerable_sets_severity(self):
        results = [self._vuln(Severity.HIGH)]
        s = self.attack.score(results)
        assert s.worst_severity == Severity.HIGH

    def test_critical_beats_high(self):
        results = [
            self._vuln(Severity.HIGH),
            self._vuln(Severity.CRITICAL),
        ]
        s = self.attack.score(results)
        assert s.worst_severity == Severity.CRITICAL

    def test_partial_counts_toward_worst_severity(self):
        results = [
            AttackResult(attack_name="dummy", variant="v",
                         status=Status.PARTIAL, severity=Severity.CRITICAL),
        ]
        s = self.attack.score(results)
        assert s.worst_severity == Severity.CRITICAL

    def test_severity_ordering_critical_high_medium_low_info(self):
        # Only LOW finding; worst should be LOW
        results = [self._vuln(Severity.LOW)]
        s = self.attack.score(results)
        assert s.worst_severity == Severity.LOW


# ---------------------------------------------------------------------------
# Score.pass_rate
# ---------------------------------------------------------------------------

class TestScorePassRate:
    def test_zero_variants_gives_zero(self):
        s = Score(attack_name="x", category="y", total_variants=0, defended=0)
        assert s.pass_rate == 0.0

    def test_all_defended(self):
        s = Score(attack_name="x", category="y", total_variants=4, defended=4)
        assert s.pass_rate == 1.0

    def test_half_defended(self):
        s = Score(attack_name="x", category="y", total_variants=4, defended=2)
        assert s.pass_rate == 0.5

    def test_none_defended(self):
        s = Score(attack_name="x", category="y", total_variants=3, defended=0, vulnerable=3)
        assert s.pass_rate == 0.0


# ---------------------------------------------------------------------------
# aggregate_scores()
# ---------------------------------------------------------------------------

class TestAggregateScores:
    def _score(self, name, category, vulnerable=0, partial=0, defended=0,
               errors=0, worst_severity=Severity.INFO, results=None) -> Score:
        total = vulnerable + partial + defended + errors
        return Score(
            attack_name=name,
            category=category,
            total_variants=total,
            vulnerable=vulnerable,
            partial=partial,
            defended=defended,
            errors=errors,
            worst_severity=worst_severity,
            results=results or [],
        )

    def test_empty_scores(self):
        result = aggregate_scores([])
        assert result["total_attacks"] == 0
        assert result["total_variants"] == 0
        assert result["total_vulnerable"] == 0
        assert result["worst_severity"] == Severity.INFO

    def test_sums_totals(self):
        scores = [
            self._score("a1", "auth", vulnerable=2, defended=1),
            self._score("a2", "auth", vulnerable=1, partial=1, defended=2),
        ]
        result = aggregate_scores(scores)
        assert result["total_attacks"] == 2
        assert result["total_variants"] == 7
        assert result["total_vulnerable"] == 3
        assert result["total_partial"] == 1
        assert result["total_defended"] == 3

    def test_groups_by_category(self):
        scores = [
            self._score("a1", "auth", vulnerable=1),
            self._score("a2", "auth", defended=2),
            self._score("i1", "injection", partial=1),
        ]
        result = aggregate_scores(scores)
        assert "auth" in result["by_category"]
        assert "injection" in result["by_category"]
        assert result["by_category"]["auth"]["attacks"] == 2
        assert result["by_category"]["auth"]["vulnerable"] == 1
        assert result["by_category"]["auth"]["defended"] == 2
        assert result["by_category"]["injection"]["attacks"] == 1
        assert result["by_category"]["injection"]["partial"] == 1

    def test_by_severity_counts_findings(self):
        vuln_result = AttackResult(
            attack_name="x", variant="v",
            status=Status.VULNERABLE, severity=Severity.HIGH,
        )
        partial_result = AttackResult(
            attack_name="x", variant="v2",
            status=Status.PARTIAL, severity=Severity.MEDIUM,
        )
        defended_result = AttackResult(
            attack_name="x", variant="v3",
            status=Status.DEFENDED, severity=Severity.CRITICAL,
        )
        s = Score(
            attack_name="x", category="test",
            total_variants=3, vulnerable=1, partial=1, defended=1,
            worst_severity=Severity.HIGH,
            results=[vuln_result, partial_result, defended_result],
        )
        result = aggregate_scores([s])
        # Only vulnerable + partial count toward by_severity
        assert result["by_severity"]["high"] == 1
        assert result["by_severity"]["medium"] == 1
        assert result["by_severity"]["critical"] == 0  # defended, not a finding

    def test_worst_severity_propagated(self):
        scores = [
            self._score("a1", "auth", vulnerable=1, worst_severity=Severity.HIGH),
            self._score("a2", "injection", vulnerable=1, worst_severity=Severity.CRITICAL),
        ]
        result = aggregate_scores(scores)
        assert result["worst_severity"] == Severity.CRITICAL

    def test_no_findings_worst_severity_stays_info(self):
        scores = [
            self._score("a1", "auth", defended=3, worst_severity=Severity.INFO),
        ]
        result = aggregate_scores(scores)
        assert result["worst_severity"] == Severity.INFO

    def test_scores_list_included_in_output(self):
        scores = [self._score("a1", "auth")]
        result = aggregate_scores(scores)
        assert result["scores"] is scores
```

## Steps

1. Write `tests/test_scoring.py` (tests first)
2. Run: `pytest tests/test_scoring.py -v` - verify failures (red)
3. Write `redteam/base.py`
4. Write `redteam/scoring.py`
5. Run: `pytest tests/test_scoring.py -v` - verify passes (green)
6. Commit: `git add -A && git commit -m "feat: core abstractions - Attack, AttackResult, Score, severity"`
