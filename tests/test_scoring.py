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
