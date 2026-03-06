"""Tests for the reporter modules: console, json_report, html."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from pathlib import Path

from redteam.base import AttackResult, Score, Severity, Status
from redteam.scoring import aggregate_scores
from redteam.reporters.console import ConsoleReporter
from redteam.reporters.json_report import JsonReporter
from redteam.reporters.html import HtmlReporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_result(attack_name="Test Attack", variant="v1", status=Status.VULNERABLE,
                 severity=Severity.HIGH, evidence="leaked data", details="Found issue",
                 duration_ms=150.0) -> AttackResult:
    return AttackResult(
        attack_name=attack_name,
        variant=variant,
        status=status,
        severity=severity,
        evidence=evidence,
        details=details,
        request={"prompt": "test prompt"},
        response={"text": "test response"},
        duration_ms=duration_ms,
    )


def _make_score(name="Test Attack", category="ai", vulnerable=1, partial=0,
                defended=1, errors=0, worst_severity=Severity.HIGH,
                results=None) -> Score:
    if results is None:
        results = []
        if vulnerable > 0:
            results.append(_make_result(attack_name=name, status=Status.VULNERABLE,
                                        severity=worst_severity))
        if defended > 0:
            results.append(_make_result(attack_name=name, variant="v2",
                                        status=Status.DEFENDED, severity=Severity.INFO,
                                        evidence="", details=""))
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
        results=results,
    )


def _make_summary(scores=None) -> dict:
    if scores is None:
        scores = [
            _make_score("Jailbreak", "ai", vulnerable=2, defended=1,
                        worst_severity=Severity.HIGH),
            _make_score("Auth Bypass", "api", vulnerable=0, defended=3,
                        worst_severity=Severity.INFO),
            _make_score("Prompt Leak", "ai", vulnerable=1, partial=1, defended=0,
                        worst_severity=Severity.CRITICAL),
        ]
    return aggregate_scores(scores)


# ---------------------------------------------------------------------------
# ConsoleReporter
# ---------------------------------------------------------------------------

class TestConsoleReporter:
    def setup_method(self):
        self.reporter = ConsoleReporter()

    def test_print_report_does_not_raise(self):
        """Smoke test: printing a full report should not crash."""
        summary = _make_summary()
        # Redirect console to suppress output during test
        from io import StringIO
        from rich.console import Console
        self.reporter.console = Console(file=StringIO())
        self.reporter.print_report(summary)

    def test_print_report_with_no_findings(self):
        """Report with all defended should show success message."""
        scores = [_make_score("Safe Attack", "ai", vulnerable=0, partial=0,
                              defended=3, worst_severity=Severity.INFO,
                              results=[
                                  _make_result(status=Status.DEFENDED, severity=Severity.INFO,
                                               evidence="", details=""),
                                  _make_result(variant="v2", status=Status.DEFENDED,
                                               severity=Severity.INFO, evidence="", details=""),
                                  _make_result(variant="v3", status=Status.DEFENDED,
                                               severity=Severity.INFO, evidence="", details=""),
                              ])]
        summary = aggregate_scores(scores)
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        self.reporter.console = Console(file=buf)
        self.reporter.print_report(summary)
        output = buf.getvalue()
        assert "defended" in output.lower() or "All attacks" in output

    def test_print_report_with_vulnerabilities(self):
        """Report with findings should include severity and evidence."""
        summary = _make_summary()
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        self.reporter.console = Console(file=buf, width=200)
        self.reporter.print_report(summary)
        output = buf.getvalue()
        assert "Security Red Team Report" in output

    def test_print_attack_list_does_not_raise(self):
        """Smoke test: listing attacks should not crash."""
        attacks = [
            {"key": "ai.jailbreak", "name": "Jailbreak", "category": "ai",
             "severity": "high", "description": "Test jailbreak resistance"},
            {"key": "api.auth", "name": "Auth Bypass", "category": "api",
             "severity": "critical", "description": "Test auth controls"},
        ]
        from io import StringIO
        from rich.console import Console
        self.reporter.console = Console(file=StringIO())
        self.reporter.print_attack_list(attacks)

    def test_print_attack_list_output_contains_keys(self):
        """Attack list should show attack keys."""
        attacks = [
            {"key": "ai.jailbreak", "name": "Jailbreak", "category": "ai",
             "severity": "high", "description": "Test jailbreak resistance"},
        ]
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        self.reporter.console = Console(file=buf, width=200)
        self.reporter.print_attack_list(attacks)
        output = buf.getvalue()
        assert "ai.jailbreak" in output
        assert "Jailbreak" in output

    def test_print_report_empty_scores(self):
        """Edge case: empty score list should not crash."""
        summary = aggregate_scores([])
        from io import StringIO
        from rich.console import Console
        self.reporter.console = Console(file=StringIO())
        self.reporter.print_report(summary)


# ---------------------------------------------------------------------------
# JsonReporter
# ---------------------------------------------------------------------------

class TestJsonReporter:
    def setup_method(self):
        self.reporter = JsonReporter()

    def test_write_report_creates_file(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        assert os.path.exists(path)
        assert path.endswith(".json")

    def test_write_report_valid_json(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_report_contains_totals(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "total_attacks" in data
        assert "total_variants" in data
        assert "total_vulnerable" in data
        assert "total_partial" in data
        assert "total_defended" in data
        assert "total_errors" in data
        assert data["total_attacks"] == 3

    def test_report_contains_severity(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "worst_severity" in data
        assert data["worst_severity"] in ["critical", "high", "medium", "low", "info"]

    def test_report_contains_findings(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0

    def test_finding_has_required_fields(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        finding = data["findings"][0]
        assert "attack" in finding
        assert "variant" in finding
        assert "status" in finding
        assert "severity" in finding
        assert "duration_ms" in finding

    def test_report_contains_by_category(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "by_category" in data
        assert "ai" in data["by_category"]

    def test_report_contains_generated_timestamp(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert "generated" in data

    def test_filename_contains_timestamp(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        filename = os.path.basename(path)
        assert filename.startswith("redteam-report-")
        assert filename.endswith(".json")

    def test_empty_summary(self, tmp_path):
        summary = aggregate_scores([])
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert data["total_attacks"] == 0
        assert data["findings"] == []


# ---------------------------------------------------------------------------
# HtmlReporter
# ---------------------------------------------------------------------------

class TestHtmlReporter:
    def setup_method(self):
        self.reporter = HtmlReporter()

    def test_write_report_creates_file(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        assert os.path.exists(path)
        assert path.endswith(".html")

    def test_report_is_valid_html(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert content.startswith("<!DOCTYPE html>")
        assert "</html>" in content

    def test_report_contains_title(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "Security Red Team Report" in content

    def test_report_contains_summary_stats(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "Attacks" in content
        assert "Variants" in content
        assert "Vulnerable" in content
        assert "Defended" in content

    def test_report_contains_category_table(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "Results by Category" in content
        assert "AI" in content

    def test_report_contains_findings_section(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "Findings" in content

    def test_report_contains_css(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        assert "<style>" in content
        assert "background:" in content

    def test_filename_contains_timestamp(self, tmp_path):
        summary = _make_summary()
        path = self.reporter.write_report(summary, str(tmp_path))
        filename = os.path.basename(path)
        assert filename.startswith("redteam-report-")
        assert filename.endswith(".html")

    def test_full_evidence_in_html(self, tmp_path):
        """Full evidence should be included in HTML for reproduction."""
        long_evidence = "A" * 1000
        results = [_make_result(evidence=long_evidence)]
        scores = [_make_score("Long Evidence", "ai", vulnerable=1, defended=0,
                              worst_severity=Severity.HIGH, results=results)]
        summary = aggregate_scores(scores)
        path = self.reporter.write_report(summary, str(tmp_path))
        with open(path) as f:
            content = f.read()
        # Full evidence is included for reproduction
        assert "A" * 1000 in content

    def test_empty_summary(self, tmp_path):
        summary = aggregate_scores([])
        path = self.reporter.write_report(summary, str(tmp_path))
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
