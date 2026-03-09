"""Hierarchical JSON report generator following ideal report structure.

This reporter generates comprehensive security scan reports in a hierarchical format
that preserves the attack → variant relationship and includes complete scan context.

Report Structure:
    - scan_metadata: Scan identification and target information
    - summary: Aggregated statistics by category and severity
    - attacks: Hierarchical array of attack results with nested variants
    - scan_config: Configuration snapshot for reproducibility

Key Features:
    - Unique scan_id for tracking (format: scan-{timestamp}-{uuid6})
    - Target metadata (URL, name, environment, type)
    - Execution metadata (mode, duration, timestamps)
    - Attack-level rollup statistics
    - Nested variant results under each attack
    - Structured evidence (summary, technical_details, proof)
    - Compliance mappings (when available)
    - Backward compatibility with flat findings array

Usage:
    >>> from redteam.reporters.hierarchical_json import HierarchicalJsonReporter
    >>> from redteam.scoring import aggregate_scores
    >>>
    >>> # After running attacks
    >>> summary = aggregate_scores(scores)
    >>> reporter = HierarchicalJsonReporter(config)
    >>> report_path = reporter.write_report(summary, "reports/")
    >>> print(f"Report written to: {report_path}")

Configuration Requirements:
    The config dict should include:
        target:
            url: Target URL
            name: Optional target name
            environment: production/staging/development
            type: app/wordpress/generic/cloud
        execution:
            mode: full/aws
            start_time: ISO timestamp
            scanner_version: Version string
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4


class HierarchicalJsonReporter:
    """Generate hierarchical JSON reports with complete scan context.

    This reporter creates comprehensive security scan reports following the
    ideal hierarchical structure defined in IDEAL_REPORT_STRUCTURE.md.

    Attributes:
        config (dict): Scanner configuration including target and execution metadata

    Example:
        >>> config = {
        ...     "target": {
        ...         "base_url": "https://keystone.quigs.com",
        ...         "name": "Project Keystone",
        ...         "environment": "production",
        ...         "type": "app"
        ...     },
        ...     "execution": {
        ...         "mode": "full",
        ...         "start_time": "2026-03-08T18:43:15.000000"
        ...     }
        ... }
        >>> reporter = HierarchicalJsonReporter(config)
        >>> path = reporter.write_report(summary, "reports/")
    """

    def __init__(self, config: dict):
        """Initialize reporter with scanner configuration.

        Args:
            config: Scanner configuration dict containing target and execution metadata
        """
        self.config = config

    def write_report(self, summary: dict, output_dir: str) -> str:
        """Generate and write hierarchical JSON report.

        Args:
            summary: Aggregated summary from aggregate_scores()
            output_dir: Directory to write report file

        Returns:
            str: Absolute path to generated report file

        Example:
            >>> reporter = HierarchicalJsonReporter(config)
            >>> summary = aggregate_scores(scores)
            >>> path = reporter.write_report(summary, "reports/")
            >>> # Report saved to: reports/hierarchical-20260308_184540.json
        """
        timestamp = datetime.now()
        timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
        path = Path(output_dir) / f"hierarchical-{timestamp_str}.json"

        report = self._build_report(summary, timestamp)

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str))
        return str(path.absolute())

    def _build_report(self, summary: dict, timestamp: datetime) -> dict:
        """Build complete hierarchical report structure.

        Args:
            summary: Aggregated summary from aggregate_scores()
            timestamp: Report generation timestamp

        Returns:
            dict: Complete report structure
        """
        # Generate unique scan ID
        scan_id = self._generate_scan_id(timestamp)

        # Build report sections
        report = {
            "scan_metadata": self._build_scan_metadata(scan_id, timestamp),
            "summary": self._build_summary(summary),
            "attacks": self._build_attacks(summary),
            "scan_config": self._build_scan_config(),
        }

        # Add backward-compatible flat findings array
        report["findings"] = self._build_flat_findings(summary)

        return report

    def _generate_scan_id(self, timestamp: datetime) -> str:
        """Generate unique scan identifier.

        Format: scan-{timestamp}-{uuid6}
        Example: scan-20260308-184540-a8f3d2

        Args:
            timestamp: Scan timestamp

        Returns:
            str: Unique scan identifier
        """
        ts_str = timestamp.strftime("%Y%m%d-%H%M%S")
        uuid_short = uuid4().hex[:6]
        return f"scan-{ts_str}-{uuid_short}"

    def _build_scan_metadata(self, scan_id: str, timestamp: datetime) -> dict:
        """Build scan_metadata section.

        Args:
            scan_id: Unique scan identifier
            timestamp: Report generation timestamp

        Returns:
            dict: Scan metadata structure
        """
        target_config = self.config.get("target", {})
        execution_config = self.config.get("execution", {})

        # Extract target URL from base_url
        base_url = target_config.get("base_url", "")
        target_name = target_config.get("name", "")

        # Calculate duration if start_time available
        start_time_str = execution_config.get("start_time")
        duration_ms = None
        if start_time_str:
            try:
                start_time = datetime.fromisoformat(start_time_str)
                duration_ms = (timestamp - start_time).total_seconds() * 1000
            except (ValueError, TypeError):
                pass

        metadata = {
            "scan_id": scan_id,
            "generated": timestamp.isoformat(),
            "scanner_version": execution_config.get("scanner_version", "1.0.0"),
            "config_hash": execution_config.get("config_hash"),
            "target": {
                "url": base_url,
                "name": target_name or base_url,
                "environment": target_config.get("environment", "unknown"),
                "type": target_config.get("type", "app"),
                "origin_ip": target_config.get("origin_ip"),
            },
            "execution": {
                "mode": execution_config.get("mode", "full"),
                "duration_ms": round(duration_ms, 2) if duration_ms else None,
                "start_time": start_time_str,
                "end_time": timestamp.isoformat(),
                "operator": execution_config.get("operator", "automated"),
            },
        }

        return metadata

    def _build_summary(self, summary: dict) -> dict:
        """Build summary statistics section.

        Args:
            summary: Aggregated summary from aggregate_scores()

        Returns:
            dict: Summary statistics structure
        """
        return {
            "attacks_executed": summary["total_attacks"],
            "variants_tested": summary["total_variants"],
            "findings": {
                "vulnerable": summary["total_vulnerable"],
                "partial": summary["total_partial"],
                "defended": summary["total_defended"],
                "errors": summary["total_errors"],
                "skipped": summary["total_skipped"],
                "not_assessed": summary["total_not_assessed"],
            },
            "severity": summary["by_severity"],
            "by_category": summary["by_category"],
        }

    def _build_attacks(self, summary: dict) -> list[dict]:
        """Build hierarchical attacks array with nested variants.

        Args:
            summary: Aggregated summary from aggregate_scores()

        Returns:
            list[dict]: Attack results with nested variant arrays
        """
        attacks = []

        for score in summary["scores"]:
            attack = {
                "attack_id": score.attack_name,
                "name": self._format_attack_name(score.attack_name),
                "category": score.category,
                "description": self._get_attack_description(score),
                "compliance": self._get_compliance_mappings(score.attack_name),
                "target_types": ["app"],  # Could be extracted from attack metadata
                "default_severity": score.worst_severity.value,
                "duration_ms": round(score.duration_ms, 1),
                "results_summary": {
                    "variants_tested": score.total_variants,
                    "vulnerable": score.vulnerable,
                    "partial": score.partial,
                    "defended": score.defended,
                    "errors": score.errors,
                    "skipped": score.skipped,
                    "not_assessed": score.not_assessed,
                },
                "variants": self._build_variants(score.results),
            }

            attacks.append(attack)

        return attacks

    def _build_variants(self, results: list) -> list[dict]:
        """Build variant results array for an attack.

        Args:
            results: List of AttackResult objects

        Returns:
            list[dict]: Variant result structures
        """
        variants = []

        for result in results:
            variant = {
                "variant_id": result.variant,
                "name": self._format_variant_name(result.variant),
                "status": result.status.value,
                "severity": result.severity.value,
                "duration_ms": round(result.duration_ms, 1),
                "evidence": self._build_evidence(result),
                "request": result.request,
                "response": result.response,
                "recommendation": self._build_recommendation(result),
            }

            variants.append(variant)

        return variants

    def _build_evidence(self, result) -> dict:
        """Build structured evidence from AttackResult.

        Args:
            result: AttackResult object

        Returns:
            dict: Structured evidence with summary, details, and proof
        """
        # Try to extract structured proof from request/response
        proof = {}

        if result.request:
            # Extract relevant request metadata
            if "attempts" in result.request:
                proof["requests_sent"] = result.request["attempts"]
            if "method" in result.request:
                proof["method"] = result.request["method"]

        if result.response:
            # Extract relevant response metadata
            if "status_codes" in result.response:
                proof["status_codes"] = result.response["status_codes"]
            if "lockout_triggered" in result.response:
                proof["lockout_triggered"] = result.response["lockout_triggered"]

        return {
            "summary": result.evidence or "No evidence recorded",
            "technical_details": result.details or "",
            "proof": proof,
        }

    def _build_recommendation(self, result) -> dict:
        """Build recommendation structure from AttackResult.

        Args:
            result: AttackResult object

        Returns:
            dict: Recommendation with priority and references
        """
        # Map severity to priority
        priority_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "informational",
        }

        priority = priority_map.get(result.severity.value, "medium")

        # Generic remediation based on status
        remediation = ""
        if result.status.value == "vulnerable":
            remediation = f"Address {result.attack_name} vulnerability: {result.evidence}"
        elif result.status.value == "partial":
            remediation = f"Improve defenses for {result.attack_name}: {result.details}"

        return {
            "priority": priority,
            "remediation": remediation,
            "references": [],  # Could be populated from attack metadata
        }

    def _build_scan_config(self) -> dict:
        """Build scan configuration snapshot.

        Returns:
            dict: Configuration snapshot for reproducibility
        """
        execution_config = self.config.get("execution", {})

        return {
            "execution_mode": execution_config.get("mode", "full"),
            "rate_limit_testing": execution_config.get("rate_limit_testing", False),
            "rate_limit_test_ip": execution_config.get("rate_limit_test_ip"),
            "cleanup_enabled": self.config.get("cleanup", {}).get("enabled", True),
            "ai_attacker_enabled": self.config.get("ai_attacker", {}).get("enabled", False),
            "models": {
                "attacker": self.config.get("ai_attacker", {}).get("attacker_model"),
                "judge": self.config.get("ai_attacker", {}).get("judge_model"),
            },
            "throttles": execution_config.get("aws", {}).get("throttle", {}),
            "skip_attacks": execution_config.get("aws", {}).get("skip_attacks", []),
        }

    def _build_flat_findings(self, summary: dict) -> list[dict]:
        """Build backward-compatible flat findings array.

        Args:
            summary: Aggregated summary from aggregate_scores()

        Returns:
            list[dict]: Flat findings array (legacy format)
        """
        findings = []

        for score in summary["scores"]:
            for result in score.results:
                findings.append({
                    "attack": result.attack_name,
                    "variant": result.variant,
                    "status": result.status.value,
                    "severity": result.severity.value,
                    "evidence": result.evidence,
                    "details": result.details,
                    "request": result.request,
                    "response": result.response,
                    "duration_ms": result.duration_ms,
                })

        return findings

    def _format_attack_name(self, attack_id: str) -> str:
        """Convert attack_id to human-readable name.

        Example: "api.account_lockout_bypass" → "Account Lockout Bypass"

        Args:
            attack_id: Attack identifier (e.g., "api.account_lockout_bypass")

        Returns:
            str: Human-readable attack name
        """
        # Remove category prefix
        if "." in attack_id:
            name_part = attack_id.split(".", 1)[1]
        else:
            name_part = attack_id

        # Convert underscores to spaces and title case
        return name_part.replace("_", " ").title()

    def _format_variant_name(self, variant_id: str) -> str:
        """Convert variant_id to human-readable name.

        Example: "rapid_attempts" → "Rapid Attempts"

        Args:
            variant_id: Variant identifier

        Returns:
            str: Human-readable variant name
        """
        return variant_id.replace("_", " ").title()

    def _get_attack_description(self, score) -> str:
        """Get attack description from score results.

        This is a placeholder that returns a generic description.
        In the future, this could query an attack_catalog table.

        Args:
            score: Score object containing attack metadata

        Returns:
            str: Attack description
        """
        # Placeholder - would ideally query attack_catalog
        return f"{self._format_attack_name(score.attack_name)} security test"

    def _get_compliance_mappings(self, attack_id: str) -> list[dict]:
        """Get compliance framework mappings for an attack.

        This is a placeholder that returns an empty list.
        In the future, this could query an attack_compliance table.

        Args:
            attack_id: Attack identifier

        Returns:
            list[dict]: Compliance mappings (framework, control_id)
        """
        # Placeholder - would ideally query attack_catalog/attack_compliance tables
        # Example return format:
        # [
        #     {"framework": "NIST-800-171-Rev2", "control": "3.1.8"},
        #     {"framework": "NIST-CSF", "control": "PR.AC-7"}
        # ]
        return []
