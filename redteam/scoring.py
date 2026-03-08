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
        "total_skipped": sum(s.skipped for s in scores),
        "total_not_assessed": sum(s.not_assessed for s in scores),
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
                "attacks": 0, "vulnerable": 0, "partial": 0, "defended": 0, "errors": 0,
                "skipped": 0, "not_assessed": 0, "duration_ms": 0
            }
        summary["by_category"][cat]["attacks"] += 1
        summary["by_category"][cat]["vulnerable"] += s.vulnerable
        summary["by_category"][cat]["partial"] += s.partial
        summary["by_category"][cat]["defended"] += s.defended
        summary["by_category"][cat]["errors"] += s.errors
        summary["by_category"][cat]["skipped"] += s.skipped
        summary["by_category"][cat]["not_assessed"] += s.not_assessed
        summary["by_category"][cat]["duration_ms"] += s.duration_ms

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
        Status.NOT_ASSESSED: "cyan",
    }.get(status, "white")
