"""Static PHP source code security audit via the blue team codebase scanner."""

import time
import logging
from pathlib import Path

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Map blue team scanner severity labels to red team Severity enum
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class PhpSourceAudit(Attack):
    """Static analysis of PHP source code using pattern-based scanning.

    Wraps blueteam.api.codebase_scanner.CodebaseSecurityScanner to surface
    findings (SQLi, XSS, path traversal, hardcoded creds, weak crypto,
    unsafe uploads, unsafe deserialization) as red team AttackResults.

    Activated when --path is provided. Can run standalone (no live URL needed)
    or alongside live scanning in the same run.
    """

    name = "static.php_source_audit"
    category = "static"
    severity = Severity.HIGH
    description = "Static PHP source analysis for OWASP-class vulnerabilities"
    target_types = {"static"}

    async def execute(self, client) -> list[AttackResult]:
        source_path = self._config.get("target", {}).get("source_path")
        if not source_path:
            return [AttackResult(
                attack_name=self.name,
                variant="config_check",
                status=Status.SKIPPED,
                severity=self.severity,
                evidence="No source_path configured — pass --path <dir>",
            )]

        path = Path(source_path)
        if not path.exists() or not path.is_dir():
            return [AttackResult(
                attack_name=self.name,
                variant="path_check",
                status=Status.ERROR,
                severity=self.severity,
                evidence=f"Path does not exist or is not a directory: {source_path}",
            )]

        try:
            from blueteam.api.codebase_scanner import CodebaseSecurityScanner
        except ImportError:
            return [AttackResult(
                attack_name=self.name,
                variant="import_check",
                status=Status.ERROR,
                severity=self.severity,
                evidence="blueteam.api.codebase_scanner not available",
            )]

        logger.info(f"Static PHP audit: scanning {source_path}")
        start = time.monotonic()
        scanner = CodebaseSecurityScanner(source_path)
        scan_results = scanner.scan()
        duration = (time.monotonic() - start) * 1000

        results = []
        findings = scan_results.get("findings", []) if isinstance(scan_results, dict) else scan_results

        if not findings:
            results.append(AttackResult(
                attack_name=self.name,
                variant="full_scan",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"No vulnerabilities found in {source_path}",
                duration_ms=duration,
            ))
            return results

        for finding in findings:
            sev_label = str(finding.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(sev_label, Severity.MEDIUM)
            vuln_type = finding.get("type") or finding.get("vulnerability_type", "unknown")
            file_path = finding.get("file", "")
            line = finding.get("line", "")
            snippet = finding.get("snippet") or finding.get("code", "")

            evidence = f"{file_path}:{line} — {vuln_type}"
            if snippet:
                evidence += f"\n  {snippet.strip()[:200]}"

            results.append(AttackResult(
                attack_name=self.name,
                variant=vuln_type,
                status=Status.VULNERABLE,
                severity=severity,
                evidence=evidence,
                details=finding.get("description", ""),
                duration_ms=duration,
            ))

        logger.info(f"Static audit complete: {len(results)} finding(s) in {duration:.0f}ms")
        return results

    async def cleanup(self, client) -> None:
        pass
