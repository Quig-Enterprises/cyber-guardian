"""Source code secret scanning attack module.

Scans application source files for hardcoded secrets including API keys,
passwords, private keys, and database connection strings using regex patterns.

Evaluation:
- Pattern found in source file -> VULNERABLE (with redacted evidence)
- No patterns found across all scanned files -> DEFENDED
- No source_path configured -> SKIPPED
"""

import re
import time
import logging
from pathlib import Path

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Directories to skip during source scanning
SKIP_DIRS = {"node_modules", ".git", "vendor", "__pycache__", ".tox", "dist", "build"}

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".php", ".js", ".env", ".yaml", ".yml",
    ".json", ".conf", ".cfg", ".ini", ".xml",
}


def _redact(value: str, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    """Redact a secret value, keeping only a prefix and suffix."""
    if len(value) <= keep_prefix + keep_suffix:
        return "*" * len(value)
    return value[:keep_prefix] + "****" + value[-keep_suffix:]


class SourceCodeScanAttack(Attack):
    """Scan source code files for hardcoded secrets."""

    name = "secrets.source_code"
    category = "secrets"
    severity = Severity.CRITICAL
    description = "Scan source files for hardcoded API keys, passwords, private keys, and connection strings"
    target_types = {"app", "wordpress", "generic", "static"}

    # API key patterns: AWS AKIA..., generic api_key=, bearer tokens
    API_KEY_PATTERNS = [
        re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
        re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', re.IGNORECASE),
        re.compile(r'Bearer\s+([A-Za-z0-9\-._~+/]{20,})', re.IGNORECASE),
        re.compile(r'(?:OPENAI|ANTHROPIC|STRIPE|SENDGRID|TWILIO|GITHUB|GITLAB|SLACK)_(?:API_)?(?:KEY|TOKEN|SECRET)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', re.IGNORECASE),
    ]

    # Password patterns — exclude test/example/placeholder values
    PASSWORD_PATTERNS = [
        re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\'](?!(?:test|example|placeholder|changeme|yourpassword|xxx|abc|123|\*|\$\{)["\']?)([^"\']{6,})["\']', re.IGNORECASE),
        re.compile(r'(?:secret|auth_secret|app_secret)\s*[:=]\s*["\'](?!(?:test|example|placeholder|changeme)["\']?)([^"\']{6,})["\']', re.IGNORECASE),
    ]

    # Private key headers
    PRIVATE_KEY_PATTERNS = [
        re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        re.compile(r'-----BEGIN PRIVATE KEY-----'),
        re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
    ]

    # Database connection string patterns
    CONNECTION_STRING_PATTERNS = [
        re.compile(r'postgresql://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
        re.compile(r'postgres://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
        re.compile(r'mysql://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
        re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
        re.compile(r'redis://:[^@]+@[^\s"\']+', re.IGNORECASE),
        re.compile(r'amqp://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
    ]

    def _get_source_path(self) -> Path | None:
        """Return the configured source path, or None if not set."""
        sp = self._config.get("target", {}).get("source_path")
        if not sp:
            return None
        p = Path(sp)
        return p if p.exists() else None

    def _iter_source_files(self, source_path: Path):
        """Yield all scannable source files, skipping excluded directories."""
        for ext in SCAN_EXTENSIONS:
            for fpath in source_path.rglob(f"*{ext}"):
                # Skip any path component that is in SKIP_DIRS
                if any(part in SKIP_DIRS for part in fpath.parts):
                    continue
                yield fpath

    def _scan_file(self, fpath: Path, patterns: list[re.Pattern]) -> list[tuple[int, str, str]]:
        """Scan a single file for pattern matches. Returns list of (line_no, pattern_desc, redacted_value)."""
        findings = []
        try:
            content = fpath.read_text(errors="replace")
            for line_no, line in enumerate(content.splitlines(), 1):
                for pat in patterns:
                    m = pat.search(line)
                    if m:
                        # Use first capture group if present, else full match
                        raw_value = m.group(1) if m.lastindex else m.group(0)
                        findings.append((line_no, pat.pattern[:40], _redact(raw_value)))
        except (OSError, PermissionError) as e:
            logger.debug("Cannot read %s: %s", fpath, e)
        return findings

    async def execute(self, client) -> list[AttackResult]:
        results = []
        results.append(await self._scan_api_keys())
        results.append(await self._scan_passwords())
        results.append(await self._scan_private_keys())
        results.append(await self._scan_connection_strings())
        return results

    async def _scan_api_keys(self) -> AttackResult:
        start = time.monotonic()
        source_path = self._get_source_path()
        if source_path is None:
            return self._make_result(
                variant="api_keys",
                status=Status.SKIPPED,
                evidence="No source_path configured in target config",
                details="Set target.source_path to enable source code scanning",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        all_findings: list[tuple[Path, int, str, str]] = []
        files_scanned = 0

        for fpath in self._iter_source_files(source_path):
            files_scanned += 1
            matches = self._scan_file(fpath, self.API_KEY_PATTERNS)
            for line_no, pat_desc, redacted in matches:
                all_findings.append((fpath, line_no, pat_desc, redacted))

        duration = (time.monotonic() - start) * 1000
        if all_findings:
            evidence_lines = [
                f"{f.relative_to(source_path)}:{ln} matched '{pd}' → value={rv}"
                for f, ln, pd, rv in all_findings[:10]
            ]
            return self._make_result(
                variant="api_keys",
                status=Status.VULNERABLE,
                evidence="\n".join(evidence_lines),
                details=(
                    f"Found {len(all_findings)} API key pattern(s) across {files_scanned} files. "
                    "Values redacted in evidence. Review and rotate any exposed keys immediately."
                ),
                request={"source_path": str(source_path), "files_scanned": files_scanned},
                response={"findings_count": len(all_findings)},
                duration_ms=duration,
            )

        return self._make_result(
            variant="api_keys",
            status=Status.DEFENDED,
            evidence=f"No API key patterns found in {files_scanned} scanned files",
            details="Scanned for AWS AKIA keys, generic api_key= assignments, and Bearer tokens",
            request={"source_path": str(source_path), "files_scanned": files_scanned},
            duration_ms=duration,
        )

    async def _scan_passwords(self) -> AttackResult:
        start = time.monotonic()
        source_path = self._get_source_path()
        if source_path is None:
            return self._make_result(
                variant="passwords",
                status=Status.SKIPPED,
                evidence="No source_path configured in target config",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        all_findings: list[tuple[Path, int, str, str]] = []
        files_scanned = 0

        for fpath in self._iter_source_files(source_path):
            files_scanned += 1
            matches = self._scan_file(fpath, self.PASSWORD_PATTERNS)
            for line_no, pat_desc, redacted in matches:
                all_findings.append((fpath, line_no, pat_desc, redacted))

        duration = (time.monotonic() - start) * 1000
        if all_findings:
            evidence_lines = [
                f"{f.relative_to(source_path)}:{ln} matched '{pd}' → value={rv}"
                for f, ln, pd, rv in all_findings[:10]
            ]
            return self._make_result(
                variant="passwords",
                status=Status.VULNERABLE,
                evidence="\n".join(evidence_lines),
                details=(
                    f"Found {len(all_findings)} hardcoded password pattern(s) across {files_scanned} files. "
                    "Test/example/placeholder values excluded. Values redacted in evidence."
                ),
                request={"source_path": str(source_path), "files_scanned": files_scanned},
                response={"findings_count": len(all_findings)},
                duration_ms=duration,
            )

        return self._make_result(
            variant="passwords",
            status=Status.DEFENDED,
            evidence=f"No hardcoded password patterns found in {files_scanned} files",
            details="Scanned for password=, passwd=, secret= assignments (excluding test/example patterns)",
            request={"source_path": str(source_path), "files_scanned": files_scanned},
            duration_ms=duration,
        )

    async def _scan_private_keys(self) -> AttackResult:
        start = time.monotonic()
        source_path = self._get_source_path()
        if source_path is None:
            return self._make_result(
                variant="private_keys",
                status=Status.SKIPPED,
                evidence="No source_path configured in target config",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        all_findings: list[tuple[Path, int, str]] = []
        files_scanned = 0

        for fpath in self._iter_source_files(source_path):
            files_scanned += 1
            try:
                content = fpath.read_text(errors="replace")
                for line_no, line in enumerate(content.splitlines(), 1):
                    for pat in self.PRIVATE_KEY_PATTERNS:
                        if pat.search(line):
                            all_findings.append((fpath, line_no, pat.pattern))
                            break
            except (OSError, PermissionError) as e:
                logger.debug("Cannot read %s: %s", fpath, e)

        duration = (time.monotonic() - start) * 1000
        if all_findings:
            evidence_lines = [
                f"{f.relative_to(source_path)}:{ln} contains '{hdr}'"
                for f, ln, hdr in all_findings[:10]
            ]
            return self._make_result(
                variant="private_keys",
                status=Status.VULNERABLE,
                evidence="\n".join(evidence_lines),
                details=(
                    f"Found {len(all_findings)} PEM/private key header(s) in source files. "
                    "Private keys must never be committed to source control."
                ),
                request={"source_path": str(source_path), "files_scanned": files_scanned},
                response={"findings_count": len(all_findings)},
                duration_ms=duration,
            )

        return self._make_result(
            variant="private_keys",
            status=Status.DEFENDED,
            evidence=f"No PEM/private key headers found in {files_scanned} files",
            details="Scanned for BEGIN RSA/OPENSSH/EC/DSA PRIVATE KEY headers",
            request={"source_path": str(source_path), "files_scanned": files_scanned},
            duration_ms=duration,
        )

    async def _scan_connection_strings(self) -> AttackResult:
        start = time.monotonic()
        source_path = self._get_source_path()
        if source_path is None:
            return self._make_result(
                variant="connection_strings",
                status=Status.SKIPPED,
                evidence="No source_path configured in target config",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        all_findings: list[tuple[Path, int, str, str]] = []
        files_scanned = 0

        for fpath in self._iter_source_files(source_path):
            files_scanned += 1
            matches = self._scan_file(fpath, self.CONNECTION_STRING_PATTERNS)
            for line_no, pat_desc, redacted in matches:
                all_findings.append((fpath, line_no, pat_desc, redacted))

        duration = (time.monotonic() - start) * 1000
        if all_findings:
            evidence_lines = [
                f"{f.relative_to(source_path)}:{ln} matched connection string → {rv}"
                for f, ln, _, rv in all_findings[:10]
            ]
            return self._make_result(
                variant="connection_strings",
                status=Status.VULNERABLE,
                evidence="\n".join(evidence_lines),
                details=(
                    f"Found {len(all_findings)} database connection string(s) with embedded credentials. "
                    "Passwords in URIs redacted. Use environment variables or a secrets manager instead."
                ),
                request={"source_path": str(source_path), "files_scanned": files_scanned},
                response={"findings_count": len(all_findings)},
                duration_ms=duration,
            )

        return self._make_result(
            variant="connection_strings",
            status=Status.DEFENDED,
            evidence=f"No database connection strings with credentials found in {files_scanned} files",
            details="Scanned for postgresql://, mysql://, mongodb://, redis:// URIs containing passwords",
            request={"source_path": str(source_path), "files_scanned": files_scanned},
            duration_ms=duration,
        )
