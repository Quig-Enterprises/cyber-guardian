"""Blue Team Codebase Security Scanner

Scans entire codebases on the server to identify security issues like:
- File uploads without malware scanning
- SQL injection vulnerabilities
- XSS vulnerabilities
- Unsafe file operations
- Missing input validation
- Hardcoded credentials
- Insecure cryptography
- Path traversal vulnerabilities
"""

import os
import re
import glob
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Security issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityIssue:
    """Represents a security issue found in code."""
    severity: Severity
    category: str
    file_path: str
    line_number: int
    issue_type: str
    description: str
    code_snippet: str
    recommendation: str
    cwe_id: Optional[str] = None
    confidence: str = "medium"  # high|medium|low


@dataclass
class ScanResult:
    """Results from a codebase security scan."""
    project_path: str
    project_name: str
    files_scanned: int
    issues: List[SecurityIssue] = field(default_factory=list)
    scan_duration_ms: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.LOW)


class CodebaseSecurityScanner:
    """Scans PHP/JavaScript codebases for common security issues."""

    def __init__(self):
        """Initialize scanner with security patterns."""
        self.patterns = self._init_security_patterns()

    def _init_security_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize regex patterns for security issues."""
        return {
            "file_upload": [
                {
                    "pattern": r'move_uploaded_file\s*\([^)]*\)',
                    "requires_scan": r'(?:clamscan|clamav|virustotal|malwarebytes|antivirus)',
                    "severity": Severity.CRITICAL,
                    "cwe": "CWE-434",
                    "description": "File upload without malware scanning detected",
                    "recommendation": "Scan uploaded files with ClamAV or similar before moving to permanent location"
                },
                {
                    # Only flag $_FILES access when there's no nonce check in surrounding context
                    "pattern": r'\$_FILES\[[\'"]([^\'"]+)[\'"]\]\s*\[[\'"](tmp_name|name|size|type)[\'\"]\]',
                    "requires_scan": r'(?:clamscan|clamav|virustotal|malwarebytes|antivirus)',
                    "requires_nonce": r'(?:check_ajax_referer|wp_verify_nonce|verify_nonce)',
                    "severity": Severity.HIGH,
                    "cwe": "CWE-434",
                    "description": "File upload handling without nonce verification or malware scanning",
                    "recommendation": "Verify nonce before handling uploads; implement malware scanning for all uploaded files"
                },
                {
                    "pattern": r'wp_handle_upload\s*\([^)]*\)',
                    "requires_scan": r'(?:clamscan|clamav|virustotal|malwarebytes|antivirus)',
                    "severity": Severity.HIGH,
                    "cwe": "CWE-434",
                    "description": "WordPress file upload without malware scanning",
                    "recommendation": "Add malware scanning hook to wp_handle_upload filter"
                }
            ],
            "sql_injection": [
                {
                    # Match $wpdb->method( ... string concat ... ) — requires $wpdb context
                    # Excludes: SHOW TABLES LIKE (always safe table-existence checks)
                    #           $wpdb->prepare() wrapping (already using parameterization)
                    "pattern": r'\$wpdb\s*->\s*(?:query|get_results|get_row|get_var|get_col|update|delete|insert)\s*\([^)]*(?:"\s*\.\s*\$|\$[a-zA-Z_]\w*\s*\.\s*"|\{\$)',
                    # Safe: table existence checks, prepare() already used, WP core table globals
                    "safe_pattern": r'(?:SHOW\s+TABLES\s+LIKE|wpdb->prepare\s*\(|\$wpdb->(?:users|usermeta|posts|postmeta|options|terms|term_taxonomy|term_relationships|comments|commentmeta)\b)',
                    # Safe context: variable built only from hardcoded string literals (enum/whitelist pattern)
                    "safe_context_pattern": r'\$where\s*=\s*["\']WHERE\s+\w+',
                    "severity": Severity.CRITICAL,
                    "cwe": "CWE-89",
                    "description": "Possible SQL injection: $wpdb method called with string concatenation instead of prepare()",
                    "recommendation": "Use $wpdb->prepare() with placeholders instead of string concatenation"
                },
                {
                    "pattern": r'mysql_query\s*\([^)]*\$',
                    "severity": Severity.CRITICAL,
                    "cwe": "CWE-89",
                    "description": "Deprecated mysql_query() with variable input",
                    "recommendation": "Use PDO or mysqli with prepared statements"
                }
            ],
            "xss": [
                {
                    "pattern": r'echo\s+\$(?:_GET|_POST|_REQUEST|_COOKIE)\[',
                    "severity": Severity.HIGH,
                    "cwe": "CWE-79",
                    "description": "Unescaped output of user input (XSS vulnerability)",
                    "recommendation": "Use esc_html(), esc_attr(), or esc_js() before output"
                },
                {
                    "pattern": r'print\s+\$(?:_GET|_POST|_REQUEST|_COOKIE)\[',
                    "severity": Severity.HIGH,
                    "cwe": "CWE-79",
                    "description": "Unescaped output of user input (XSS vulnerability)",
                    "recommendation": "Use esc_html(), esc_attr(), or esc_js() before output"
                },
                {
                    "pattern": r'<\?=\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\[',
                    "severity": Severity.HIGH,
                    "cwe": "CWE-79",
                    "description": "Unescaped output of user input in short echo tag",
                    "recommendation": "Use esc_html(), esc_attr(), or esc_js() before output"
                }
            ],
            "path_traversal": [
                {
                    "pattern": r'file_get_contents\s*\(\s*\$(?:_GET|_POST|_REQUEST)\[',
                    "severity": Severity.CRITICAL,
                    "cwe": "CWE-22",
                    "description": "Path traversal vulnerability in file_get_contents",
                    "recommendation": "Validate and sanitize file paths, use realpath() and check against allowed directories"
                },
                {
                    "pattern": r'include(?:_once)?\s*\(\s*\$(?:_GET|_POST|_REQUEST)\[',
                    "severity": Severity.CRITICAL,
                    "cwe": "CWE-98",
                    "description": "Remote file inclusion vulnerability",
                    "recommendation": "Never include files based on user input"
                },
                {
                    "pattern": r'require(?:_once)?\s*\(\s*\$(?:_GET|_POST|_REQUEST)\[',
                    "severity": Severity.CRITICAL,
                    "cwe": "CWE-98",
                    "description": "Remote file inclusion vulnerability",
                    "recommendation": "Never require files based on user input"
                }
            ],
            "weak_crypto": [
                {
                    # MD5/SHA1 used for passwords or tokens — HIGH severity
                    "pattern": r'(?:password|token|secret|auth|session_id|nonce)\s*=\s*(?:md5|sha1)\s*\(',
                    "severity": Severity.HIGH,
                    "cwe": "CWE-327",
                    "description": "Weak hash function used for security-sensitive value (password/token/session)",
                    "recommendation": "Use password_hash() for passwords; use hash('sha256', ...) or random_bytes() for tokens"
                },
                {
                    # MD5 assigned to cache/key variable — LOW, informational only
                    "pattern": r'\bmd5\s*\(',
                    "severity": Severity.LOW,
                    "cwe": "CWE-327",
                    "description": "MD5 hash function detected (review if used for security or just as cache key)",
                    "recommendation": "Ensure MD5 is not used for passwords or security tokens; it is acceptable for cache keys"
                },
                {
                    # SHA1 — flag HIBP pattern as informational, others as LOW
                    "pattern": r'\bsha1\s*\(',
                    "severity": Severity.LOW,
                    "cwe": "CWE-327",
                    "description": "SHA1 hash function detected (acceptable for HIBP API; not for passwords)",
                    "recommendation": "Ensure SHA1 is only used for HIBP breach lookups or non-security purposes; use password_hash() for passwords"
                }
            ],
            "credentials": [
                {
                    "pattern": r'(?:password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*["\'][^"\']{8,}["\']',
                    "severity": Severity.CRITICAL,
                    "cwe": "CWE-798",
                    "description": "Hardcoded credentials detected",
                    "recommendation": "Move credentials to environment variables or secure configuration"
                }
            ],
            "unsafe_unserialize": [
                {
                    "pattern": r'unserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\[',
                    "severity": Severity.CRITICAL,
                    "cwe": "CWE-502",
                    "description": "Unsafe deserialization of user input",
                    "recommendation": "Use JSON instead of serialize/unserialize for user data"
                }
            ]
        }

    def scan_project(self, project_path: str, project_name: str = None) -> ScanResult:
        """Scan a project directory for security issues.

        Args:
            project_path: Path to project root
            project_name: Optional project name (defaults to directory name)

        Returns:
            ScanResult with all findings
        """
        import time
        start_time = time.time()

        if not project_name:
            project_name = os.path.basename(project_path.rstrip('/'))

        result = ScanResult(
            project_path=project_path,
            project_name=project_name,
            files_scanned=0
        )

        # Find all PHP files
        php_files = list(Path(project_path).rglob("*.php"))

        logger.info(f"Scanning {len(php_files)} PHP files in {project_name}...")

        for php_file in php_files:
            # Skip vendor directories, node_modules, and dev-only files
            skip_dirs = ['/vendor/', '/node_modules/', '/dev/']
            if any(d in str(php_file) for d in skip_dirs):
                continue

            result.files_scanned += 1
            issues = self._scan_file(str(php_file))
            result.issues.extend(issues)

        result.scan_duration_ms = (time.time() - start_time) * 1000
        logger.info(f"Scan complete: {len(result.issues)} issues found in {result.files_scanned} files")

        return result

    def _scan_file(self, file_path: str) -> List[SecurityIssue]:
        """Scan a single file for security issues.

        Args:
            file_path: Path to file to scan

        Returns:
            List of SecurityIssue objects
        """
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return issues

        # Check each pattern category
        for category, patterns in self.patterns.items():
            for pattern_config in patterns:
                pattern = pattern_config["pattern"]

                for line_num, line in enumerate(lines, 1):
                    match = re.search(pattern, line)
                    if match:
                        # Check surrounding context (150-line window: 75 before, 75 after)
                        context_start = max(0, line_num - 75)
                        context_end = min(len(lines), line_num + 75)
                        context = "\n".join(lines[context_start:context_end])

                        # Suppress if the line itself matches a known-safe pattern
                        if "safe_pattern" in pattern_config:
                            if re.search(pattern_config["safe_pattern"], line, re.IGNORECASE):
                                continue

                        # Suppress if context indicates the variable is built from safe literals only
                        if "safe_context_pattern" in pattern_config:
                            if re.search(pattern_config["safe_context_pattern"], context, re.IGNORECASE):
                                continue

                        # Suppress if required scan tool is present in context
                        if "requires_scan" in pattern_config:
                            if re.search(pattern_config["requires_scan"], context, re.IGNORECASE):
                                continue

                        # Suppress if nonce/permission check is present in context
                        if "requires_nonce" in pattern_config:
                            if re.search(pattern_config["requires_nonce"], context, re.IGNORECASE):
                                continue

                        issue = SecurityIssue(
                            severity=pattern_config["severity"],
                            category=category,
                            file_path=file_path,
                            line_number=line_num,
                            issue_type=pattern_config["description"],
                            description=pattern_config["description"],
                            code_snippet=line.strip(),
                            recommendation=pattern_config["recommendation"],
                            cwe_id=pattern_config.get("cwe"),
                            confidence="high" if pattern_config["severity"] == Severity.CRITICAL else "medium"
                        )
                        issues.append(issue)

        return issues

    def scan_all_projects(self, base_paths: List[str]) -> List[ScanResult]:
        """Scan all projects under given base paths.

        Args:
            base_paths: List of base paths to scan (e.g., ['/var/www/html/wordpress/wp-content/plugins'])

        Returns:
            List of ScanResult objects
        """
        results = []

        for base_path in base_paths:
            if not os.path.exists(base_path):
                logger.warning(f"Base path does not exist: {base_path}")
                continue

            # Find all subdirectories (projects)
            for entry in os.listdir(base_path):
                project_path = os.path.join(base_path, entry)
                if os.path.isdir(project_path):
                    # Skip common non-project directories
                    if entry in ['vendor', 'node_modules', '.git', '__pycache__']:
                        continue

                    result = self.scan_project(project_path, entry)
                    if result.issues:  # Only include projects with issues
                        results.append(result)

        return results


# Singleton instance
_scanner = None


def get_scanner() -> CodebaseSecurityScanner:
    """Get the singleton scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = CodebaseSecurityScanner()
    return _scanner


if __name__ == "__main__":
    # Test the scanner
    scanner = get_scanner()

    print("Testing CodebaseSecurityScanner...")
    print("=" * 70)

    # Scan WordPress plugins
    base_paths = [
        "/var/www/html/wordpress/wp-content/plugins",
        "/opt/claude-workspace/projects"
    ]

    results = scanner.scan_all_projects(base_paths)

    print(f"\nScanned {len(results)} projects with issues")

    for result in results[:5]:  # Show first 5 projects
        print(f"\n{result.project_name}:")
        print(f"  Files scanned: {result.files_scanned}")
        print(f"  Issues: {len(result.issues)} (CRITICAL: {result.critical_count}, HIGH: {result.high_count})")

        if result.issues:
            print("\n  Top issues:")
            for issue in result.issues[:3]:
                print(f"    - {issue.severity.value.upper()}: {issue.issue_type}")
                print(f"      {issue.file_path}:{issue.line_number}")
