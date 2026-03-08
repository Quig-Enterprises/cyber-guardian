"""Base classes for the security red team framework."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import hashlib
import logging
import os
import time

logger = logging.getLogger(__name__)


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
    NOT_ASSESSED = "not_assessed"


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
    skipped: int = 0
    not_assessed: int = 0
    worst_severity: Severity = Severity.INFO
    results: list[AttackResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def pass_rate(self) -> float:
        assessed = self.total_variants - self.skipped - self.not_assessed
        if assessed == 0:
            return 0.0
        return self.defended / assessed

    @property
    def has_findings(self) -> bool:
        return self.vulnerable > 0 or self.partial > 0


class Attack(ABC):
    """Base class for all attack modules."""
    name: str = "unnamed"
    category: str = "unknown"
    severity: Severity = Severity.INFO
    description: str = ""
    target_types: set[str] = {"app"}

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

    # ------------------------------------------------------------------
    # Rate limit test mode
    # ------------------------------------------------------------------

    def _is_rate_limit_test_mode(self) -> bool:
        """Return True when rate_limit_testing is enabled in config.

        In this mode, rate-limit attacks use a spoofed external source IP
        so the scanner's whitelisted localhost address doesn't bypass limits.
        """
        return bool(
            self._config.get("execution", {}).get("rate_limit_testing", False)
        )

    def _get_rate_test_source_ip(self) -> str:
        """Return the external IP to spoof for rate-limit tests.

        Configurable via execution.rate_limit_test_ip; defaults to a
        non-routable external address that is definitely not whitelisted.
        """
        return self._config.get("execution", {}).get(
            "rate_limit_test_ip", "203.0.113.99"  # TEST-NET-3, RFC 5737
        )

    def _reset_rate_limit_blocks(self, emails: list[str], ips: list[str] | None = None) -> int:
        """Delete file-based rate limit records for the given email/IP combinations.

        Supports the Alfred dashboard rate limiter which stores blocks in
        /tmp/artemis_rate_limits/<sha256(ip:email)>.json

        Returns the number of files deleted.
        """
        rl_cfg = self._config.get("execution", {}).get("rate_limit_reset", {})
        dirs = rl_cfg.get("dirs", ["/tmp/artemis_rate_limits"])
        test_ip = self._get_rate_test_source_ip()
        check_ips = list(set((ips or []) + [test_ip, "127.0.0.1", "::1"]))

        deleted = 0
        for rl_dir in dirs:
            if not os.path.isdir(rl_dir):
                continue
            for email in emails:
                for ip in check_ips:
                    key = hashlib.sha256(f"{ip}:{email.lower()}".encode()).hexdigest()
                    path = os.path.join(rl_dir, f"{key}.json")
                    if os.path.exists(path):
                        try:
                            os.unlink(path)
                            deleted += 1
                            logger.debug(f"  [rate-reset] Removed block: {ip}:{email}")
                        except OSError as e:
                            logger.warning(f"  [rate-reset] Could not remove {path}: {e}")

        if deleted:
            logger.info(f"  [rate-reset] Cleared {deleted} rate limit block(s)")
        return deleted

    def _get_target_type(self) -> str:
        """Return the active target type from config."""
        return self._config.get("target", {}).get("type", "app")

    def _get_test_endpoints(self) -> list[str]:
        """Return test endpoints based on target type.

        WordPress and generic targets read from config; app returns defaults.
        """
        target_type = self._get_target_type()
        if target_type == "wordpress":
            wp = self._config.get("target", {}).get("wordpress", {})
            return [
                wp.get("rest_prefix", "/wp-json") + "/wp/v2/posts",
                wp.get("login_path", "/wp-login.php"),
            ]
        elif target_type == "generic":
            generic = self._config.get("target", {}).get("generic", {})
            return generic.get("test_endpoints", ["/"])
        else:
            return ["/api/ai_chat.php"]

    def _get_login_endpoint(self) -> str:
        """Return the login endpoint based on target type."""
        target_type = self._get_target_type()
        if target_type == "wordpress":
            return self._config.get("target", {}).get("wordpress", {}).get("login_path", "/wp-login.php")
        elif target_type == "generic":
            return self._config.get("target", {}).get("generic", {}).get("login_endpoint", "/login")
        else:
            return "/api/auth/login.php"

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
            elif r.status == Status.SKIPPED:
                score.skipped += 1
            elif r.status == Status.NOT_ASSESSED:
                score.not_assessed += 1
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
