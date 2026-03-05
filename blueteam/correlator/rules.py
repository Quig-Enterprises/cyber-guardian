"""Correlation rules — detect attack patterns from event streams."""
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from blueteam.models import SecurityEvent, SecurityIncident


class BaseRule(ABC):
    """Base class for all correlation rules."""
    name: str = "base"

    @abstractmethod
    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        ...


class BruteForceDetection(BaseRule):
    """Detect repeated login failures from same IP."""
    name = "brute_force"

    def __init__(self):
        self._alerted_ips: set[str] = set()

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        threshold = config.get("correlation", {}).get("rules", {}).get(
            "brute_force", {}
        ).get("threshold", 5)

        failures_by_ip: Counter = Counter()
        for e in events:
            if e.action in ("login", "unauthorized_request") and e.ip_address:
                if e.details.get("result") == "failure" or e.action == "unauthorized_request":
                    failures_by_ip[e.ip_address] += 1

        incidents = []
        for ip, count in failures_by_ip.items():
            if count >= threshold and ip not in self._alerted_ips:
                self._alerted_ips.add(ip)
                incidents.append(SecurityIncident(
                    title=f"Brute force detected from {ip}",
                    severity="high",
                    detected_by=self.name,
                    nist_controls=["3.1.8", "3.3.1"],
                    description=f"{count} failed login attempts from {ip}",
                ))
        return incidents


class CredentialStuffing(BaseRule):
    """Detect many failed logins across different users from same IP."""
    name = "credential_stuffing"

    def __init__(self):
        self._alerted_ips: set[str] = set()

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        threshold = config.get("correlation", {}).get("rules", {}).get(
            "credential_stuffing", {}
        ).get("threshold", 10)

        users_by_ip: dict[str, set] = defaultdict(set)
        for e in events:
            if e.action == "login" and e.details.get("result") == "failure":
                if e.ip_address and e.user_id:
                    users_by_ip[e.ip_address].add(e.user_id)

        incidents = []
        for ip, users in users_by_ip.items():
            if len(users) >= threshold and ip not in self._alerted_ips:
                self._alerted_ips.add(ip)
                incidents.append(SecurityIncident(
                    title=f"Credential stuffing from {ip}",
                    severity="critical",
                    detected_by=self.name,
                    nist_controls=["3.1.8", "3.5.2"],
                    description=f"{len(users)} distinct users targeted from {ip}",
                ))
        return incidents


class PrivilegeEscalation(BaseRule):
    """Detect role changes or impersonation events."""
    name = "privilege_escalation"

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        incidents = []
        for e in events:
            if e.action in ("role_change", "impersonation_start"):
                incidents.append(SecurityIncident(
                    title=f"Privilege escalation: {e.action}",
                    severity="high",
                    detected_by=self.name,
                    nist_controls=["3.1.5", "3.1.7"],
                    description=f"User {e.user_id} performed {e.action}",
                    cui_involved=e.cui_involved,
                    events=[e],
                ))
        return incidents


class AnomalousAccess(BaseRule):
    """Detect access to sensitive endpoints by non-admin users."""
    name = "anomalous_access"

    ADMIN_PATHS = {"/api/admin/", "/api/admin/users", "/api/admin/settings"}

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        incidents = []
        for e in events:
            path = e.details.get("path", "")
            if any(path.startswith(p) for p in self.ADMIN_PATHS):
                if e.action in ("forbidden_request", "unauthorized_request"):
                    incidents.append(SecurityIncident(
                        title=f"Anomalous admin access attempt",
                        severity="high",
                        detected_by=self.name,
                        nist_controls=["3.1.1", "3.1.2"],
                        description=f"IP {e.ip_address} attempted {path}",
                        events=[e],
                    ))
        return incidents


class DataExfiltration(BaseRule):
    """Detect unusually high data access rates."""
    name = "data_exfiltration"

    def __init__(self):
        self._alerted_users: set[str] = set()

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        threshold = config.get("correlation", {}).get("rules", {}).get(
            "data_exfiltration", {}
        ).get("threshold", 20)

        access_by_user: Counter = Counter()
        for e in events:
            if e.cui_involved and e.user_id:
                access_by_user[e.user_id] += 1

        incidents = []
        for user, count in access_by_user.items():
            if count >= threshold and user not in self._alerted_users:
                self._alerted_users.add(user)
                incidents.append(SecurityIncident(
                    title=f"Possible data exfiltration by {user}",
                    severity="critical",
                    detected_by=self.name,
                    nist_controls=["3.1.3", "3.8.3"],
                    description=f"{count} CUI access events from user {user}",
                    cui_involved=True,
                ))
        return incidents


class AIAbusePattern(BaseRule):
    """Detect AI guardrail triggers and abuse patterns."""
    name = "ai_abuse"

    def __init__(self):
        self._alerted_users: set[str] = set()

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        triggers_by_user: Counter = Counter()
        for e in events:
            if e.action == "guardrail_triggered" and e.user_id:
                triggers_by_user[e.user_id] += 1

        incidents = []
        for user, count in triggers_by_user.items():
            if count >= 3 and user not in self._alerted_users:
                self._alerted_users.add(user)
                incidents.append(SecurityIncident(
                    title=f"AI abuse pattern from {user}",
                    severity="high",
                    detected_by=self.name,
                    nist_controls=["3.14.6", "3.1.1"],
                    description=f"{count} guardrail triggers from user {user}",
                    events=[e for e in events if e.user_id == user and e.action == "guardrail_triggered"],
                ))
        return incidents


class AfterHoursAccess(BaseRule):
    """Flag access outside business hours (configurable)."""
    name = "after_hours"

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        incidents = []
        for e in events:
            hour = e.timestamp.hour
            if (hour < 6 or hour >= 22) and e.category == "admin":
                incidents.append(SecurityIncident(
                    title=f"After-hours admin activity",
                    severity="medium",
                    detected_by=self.name,
                    nist_controls=["3.1.1", "3.3.1"],
                    description=f"Admin action '{e.action}' at {e.timestamp.strftime('%H:%M')} UTC by {e.user_id}",
                    events=[e],
                ))
        return incidents


class AccountTakeover(BaseRule):
    """Detect password reset followed by immediate login from different IP."""
    name = "account_takeover"

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        # Track password resets per user
        reset_ips: dict[str, str] = {}
        incidents = []

        for e in sorted(events, key=lambda x: x.timestamp):
            if e.action == "password_reset_sent" and e.user_id:
                reset_ips[e.user_id] = e.ip_address or ""
            elif e.action == "login" and e.details.get("result") == "success" and e.user_id:
                if e.user_id in reset_ips:
                    reset_ip = reset_ips.pop(e.user_id)
                    if reset_ip and e.ip_address and reset_ip != e.ip_address:
                        incidents.append(SecurityIncident(
                            title=f"Possible account takeover: {e.user_id}",
                            severity="critical",
                            detected_by=self.name,
                            nist_controls=["3.5.2", "3.5.9"],
                            description=f"Password reset from {reset_ip}, login from {e.ip_address}",
                            events=[e],
                        ))
        return incidents


class SessionAnomaly(BaseRule):
    """Detect concurrent sessions from different IPs."""
    name = "session_anomaly"

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        user_ips: dict[str, set] = defaultdict(set)
        for e in events:
            if e.action == "login" and e.details.get("result") == "success":
                if e.user_id and e.ip_address:
                    user_ips[e.user_id].add(e.ip_address)

        incidents = []
        for user, ips in user_ips.items():
            if len(ips) > 2:
                incidents.append(SecurityIncident(
                    title=f"Session anomaly for {user}",
                    severity="medium",
                    detected_by=self.name,
                    nist_controls=["3.5.2", "3.1.8"],
                    description=f"User {user} active from {len(ips)} IPs: {', '.join(sorted(ips))}",
                ))
        return incidents


class AuditLogGap(BaseRule):
    """Detect gaps in audit logging (possible tamper)."""
    name = "audit_log_gap"

    def __init__(self):
        self._last_event_time: datetime | None = None

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        incidents = []
        if not events:
            return incidents

        audit_events = [e for e in events if e.source == "audit_db"]
        if not audit_events:
            return incidents

        latest = max(e.timestamp for e in audit_events)
        if self._last_event_time:
            gap = (latest - self._last_event_time).total_seconds()
            if gap > 600:  # 10 minute gap
                incidents.append(SecurityIncident(
                    title="Audit log gap detected",
                    severity="critical",
                    detected_by=self.name,
                    nist_controls=["3.3.4", "3.3.1"],
                    description=f"{int(gap)}s gap in audit events — possible tamper or system failure",
                ))
        self._last_event_time = latest
        return incidents


class RateLimitSurge(BaseRule):
    """Detect burst of rate limit hits from single source."""
    name = "rate_limit_surge"

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        hits_by_ip: Counter = Counter()
        for e in events:
            if e.action in ("rate_limit_hit", "password_reset_rate_limited"):
                if e.ip_address:
                    hits_by_ip[e.ip_address] += 1

        incidents = []
        for ip, count in hits_by_ip.items():
            if count >= 5:
                incidents.append(SecurityIncident(
                    title=f"Rate limit surge from {ip}",
                    severity="medium",
                    detected_by=self.name,
                    nist_controls=["3.14.6", "3.1.8"],
                    description=f"{count} rate limit hits from {ip}",
                ))
        return incidents


class CrossTenantAccess(BaseRule):
    """Detect access attempts across instance boundaries."""
    name = "cross_tenant"

    def evaluate(self, events: list[SecurityEvent], config: dict) -> list[SecurityIncident]:
        incidents = []
        for e in events:
            if e.action == "api_request" and e.details.get("result") == "denied":
                if "instance" in e.details.get("resource_type", "").lower():
                    incidents.append(SecurityIncident(
                        title=f"Cross-tenant access attempt",
                        severity="critical",
                        detected_by=self.name,
                        nist_controls=["3.1.1", "3.1.3", "3.4.5"],
                        description=f"User {e.user_id} denied access to instance {e.details.get('resource_id')}",
                        cui_involved=True,
                        events=[e],
                    ))
        return incidents


ALL_RULES: list[type[BaseRule]] = [
    BruteForceDetection,
    CredentialStuffing,
    PrivilegeEscalation,
    AnomalousAccess,
    DataExfiltration,
    AIAbusePattern,
    AfterHoursAccess,
    AccountTakeover,
    SessionAnomaly,
    AuditLogGap,
    RateLimitSurge,
    CrossTenantAccess,
]
