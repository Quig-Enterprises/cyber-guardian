# BT-07: Correlation Rule Engine

**Goal:** Implement a rule-based event correlation engine with 12 built-in detection rules for attack patterns, policy violations, and anomalous behavior.

**Files:**
- Create: `/opt/security-blue-team/blueteam/correlator/engine.py`
- Create: `/opt/security-blue-team/blueteam/correlator/rules.py`
- Create: `/opt/security-blue-team/tests/test_correlator.py`

**Depends on:** BT-06

---

## Step 1: Write tests for correlation engine

```python
# tests/test_correlator.py
import pytest
from datetime import datetime, timedelta, timezone
from blueteam.models import SecurityEvent, SecurityIncident
from blueteam.correlator.engine import CorrelationEngine
from blueteam.correlator.rules import BruteForceDetection

def make_event(action="login", result="failure", ip="1.2.3.4", user_id=None, minutes_ago=0):
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        source="audit_db",
        category="auth",
        severity="medium",
        action=action,
        user_id=user_id,
        ip_address=ip,
        details={"result": result},
        nist_controls=["3.1.8"],
    )

def test_brute_force_triggers_on_threshold():
    rule = BruteForceDetection(threshold=5, window_seconds=300)
    events = [make_event(minutes_ago=i) for i in range(6)]
    incident = rule.evaluate(events)
    assert incident is not None
    assert incident.severity == "high"
    assert "3.1.8" in incident.nist_controls

def test_brute_force_no_trigger_below_threshold():
    rule = BruteForceDetection(threshold=5, window_seconds=300)
    events = [make_event(minutes_ago=i) for i in range(3)]
    incident = rule.evaluate(events)
    assert incident is None

def test_engine_processes_events():
    engine = CorrelationEngine(config={})
    events = [make_event(minutes_ago=i) for i in range(6)]
    incidents = engine.process(events)
    assert isinstance(incidents, list)
```

Run: `python -m pytest tests/test_correlator.py -v` — Expected: FAIL

---

## Step 2: Implement correlation engine

```python
# blueteam/correlator/engine.py
"""Event correlation engine."""
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from blueteam.models import SecurityEvent, SecurityIncident

class CorrelationRule:
    """Base class for correlation rules."""
    name: str = "base"
    description: str = ""
    severity: str = "medium"
    nist_controls: list[str] = []

    def evaluate(self, events: list[SecurityEvent]) -> SecurityIncident | None:
        raise NotImplementedError

class CorrelationEngine:
    """Processes events through all registered correlation rules."""

    def __init__(self, config: dict):
        self.config = config
        self.rules: list[CorrelationRule] = []
        self._event_buffer: list[SecurityEvent] = []
        self._buffer_window = timedelta(seconds=config.get("correlation", {}).get("window_seconds", 300))

    def register_rule(self, rule: CorrelationRule):
        self.rules.append(rule)

    def process(self, new_events: list[SecurityEvent]) -> list[SecurityIncident]:
        """Add new events to buffer, evaluate all rules, return any incidents."""
        self._event_buffer.extend(new_events)
        self._prune_buffer()

        incidents = []
        for rule in self.rules:
            try:
                incident = rule.evaluate(self._event_buffer)
                if incident:
                    incidents.append(incident)
            except Exception as e:
                # Log but don't crash the engine
                import sys
                print(f"Rule {rule.name} failed: {e}", file=sys.stderr)
        return incidents

    def _prune_buffer(self):
        """Remove events older than the correlation window."""
        cutoff = datetime.now(timezone.utc) - self._buffer_window
        self._event_buffer = [e for e in self._event_buffer if e.timestamp > cutoff]
```

---

## Step 3: Implement 12 built-in correlation rules

```python
# blueteam/correlator/rules.py
"""Built-in correlation rules for NIST 800-171 compliance."""
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from blueteam.correlator.engine import CorrelationRule
from blueteam.models import SecurityEvent, SecurityIncident

class BruteForceDetection(CorrelationRule):
    """Detect brute force login attempts from a single IP."""
    name = "brute_force"
    description = ">N failed logins from same IP within window"
    severity = "high"
    nist_controls = ["3.1.8", "3.14.6"]

    def __init__(self, threshold: int = 5, window_seconds: int = 300):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events: list[SecurityEvent]) -> SecurityIncident | None:
        cutoff = datetime.now(timezone.utc) - self.window
        failed = [e for e in events
                  if e.category == "auth" and e.action == "login"
                  and e.details.get("result") == "failure"
                  and e.timestamp > cutoff]

        by_ip = defaultdict(list)
        for e in failed:
            if e.ip_address:
                by_ip[e.ip_address].append(e)

        for ip, ip_events in by_ip.items():
            if len(ip_events) >= self.threshold:
                return SecurityIncident(
                    title=f"Brute force attack from {ip}",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                    description=f"{len(ip_events)} failed logins from {ip} in {self.window}",
                    events=ip_events,
                )
        return None


class CredentialStuffing(CorrelationRule):
    """Detect credential stuffing — many different accounts from one IP."""
    name = "credential_stuffing"
    severity = "critical"
    nist_controls = ["3.1.8", "3.14.6"]

    def __init__(self, threshold: int = 10, window_seconds: int = 300):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events):
        cutoff = datetime.now(timezone.utc) - self.window
        failed = [e for e in events
                  if e.category == "auth" and e.details.get("result") == "failure"
                  and e.timestamp > cutoff]

        by_ip = defaultdict(set)
        for e in failed:
            if e.ip_address and e.details.get("email"):
                by_ip[e.ip_address].add(e.details["email"])

        for ip, emails in by_ip.items():
            if len(emails) >= self.threshold:
                return SecurityIncident(
                    title=f"Credential stuffing from {ip}",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                    description=f"{len(emails)} unique accounts targeted from {ip}",
                )
        return None


class PrivilegeEscalation(CorrelationRule):
    """Detect non-admin users accessing admin endpoints."""
    name = "privilege_escalation"
    severity = "critical"
    nist_controls = ["3.1.7", "3.14.7"]

    def evaluate(self, events):
        for e in events:
            if (e.category == "access"
                and e.details.get("result") == "denied"
                and e.details.get("resource_type", "").startswith("/api/admin/")):
                return SecurityIncident(
                    title=f"Privilege escalation attempt by {e.user_id}",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                    description=f"User {e.user_id} attempted {e.details.get('resource_type')}",
                    events=[e],
                )
        return None


class AnomalousAccess(CorrelationRule):
    """Detect access from unusual IP/UA for known users."""
    name = "anomalous_access"
    severity = "medium"
    nist_controls = ["3.14.7"]
    _known_ips = defaultdict(set)

    def evaluate(self, events):
        for e in events:
            if e.category == "auth" and e.action == "login" and e.details.get("result") == "success":
                if e.user_id and e.ip_address:
                    if e.user_id in self._known_ips and e.ip_address not in self._known_ips[e.user_id]:
                        return SecurityIncident(
                            title=f"New IP for user {e.user_id}: {e.ip_address}",
                            severity=self.severity,
                            detected_by=self.name,
                            nist_controls=self.nist_controls,
                            events=[e],
                        )
                    self._known_ips[e.user_id].add(e.ip_address)
        return None


class DataExfiltration(CorrelationRule):
    """Detect unusual volume of data exports/downloads."""
    name = "data_exfiltration"
    severity = "high"
    nist_controls = ["3.1.3", "3.14.6"]

    def __init__(self, threshold: int = 20, window_seconds: int = 3600):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events):
        cutoff = datetime.now(timezone.utc) - self.window
        exports = [e for e in events
                   if e.category == "data"
                   and e.action in ("export_data", "file_download", "report_generate")
                   and e.timestamp > cutoff]

        by_user = defaultdict(list)
        for e in exports:
            if e.user_id:
                by_user[e.user_id].append(e)

        for user_id, user_events in by_user.items():
            if len(user_events) >= self.threshold:
                return SecurityIncident(
                    title=f"Possible data exfiltration by {user_id}",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                    description=f"{len(user_events)} data exports in {self.window}",
                    cui_involved=True,
                    events=user_events,
                )
        return None


class AIAbusePattern(CorrelationRule):
    """Detect repeated AI guardrail triggers from same user."""
    name = "ai_abuse"
    severity = "high"
    nist_controls = ["3.14.6"]

    def __init__(self, threshold: int = 3, window_seconds: int = 600):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events):
        cutoff = datetime.now(timezone.utc) - self.window
        guardrail_events = [e for e in events
                           if e.category == "ai" and e.action == "guardrail_triggered"
                           and e.timestamp > cutoff]

        by_user = defaultdict(list)
        for e in guardrail_events:
            if e.user_id:
                by_user[e.user_id].append(e)

        for user_id, user_events in by_user.items():
            if len(user_events) >= self.threshold:
                return SecurityIncident(
                    title=f"AI abuse pattern from {user_id}",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                    description=f"{len(user_events)} guardrail triggers in {self.window}",
                    events=user_events,
                )
        return None


class AfterHoursAccess(CorrelationRule):
    """Detect CUI access outside business hours."""
    name = "after_hours_access"
    severity = "medium"
    nist_controls = ["3.14.7"]

    def evaluate(self, events):
        for e in events:
            if e.cui_involved and e.timestamp.hour not in range(6, 22):
                return SecurityIncident(
                    title=f"After-hours CUI access by {e.user_id}",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                    events=[e],
                )
        return None


class AccountTakeover(CorrelationRule):
    """Detect password change followed by data access from new IP."""
    name = "account_takeover"
    severity = "critical"
    nist_controls = ["3.5.2", "3.14.6"]

    def evaluate(self, events):
        pw_changes = {e.user_id: e for e in events
                     if e.action in ("password_reset", "password_change") and e.user_id}

        for e in events:
            if (e.category == "data" and e.user_id in pw_changes
                and e.timestamp > pw_changes[e.user_id].timestamp
                and e.ip_address != pw_changes[e.user_id].ip_address):
                return SecurityIncident(
                    title=f"Possible account takeover: {e.user_id}",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                    cui_involved=True,
                    events=[pw_changes[e.user_id], e],
                )
        return None


class SessionAnomaly(CorrelationRule):
    """Detect multiple concurrent sessions or session replay."""
    name = "session_anomaly"
    severity = "high"
    nist_controls = ["3.13.15"]

    def evaluate(self, events):
        active = defaultdict(set)
        for e in events:
            if e.category == "access" and e.user_id and e.ip_address:
                active[e.user_id].add(e.ip_address)

        for user_id, ips in active.items():
            if len(ips) > 2:
                return SecurityIncident(
                    title=f"Session anomaly: {user_id} from {len(ips)} IPs",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                )
        return None


class AuditLogGap(CorrelationRule):
    """Detect gaps in audit logging (audit failure)."""
    name = "audit_log_gap"
    severity = "critical"
    nist_controls = ["3.3.4"]

    def evaluate(self, events):
        audit_events = [e for e in events if e.source == "audit_db"]
        if not audit_events:
            return SecurityIncident(
                title="Audit log gap detected — no events in correlation window",
                severity=self.severity,
                detected_by=self.name,
                nist_controls=self.nist_controls,
                description="No audit events received. Possible logging failure (NIST 3.3.4).",
            )
        return None


class RateLimitSurge(CorrelationRule):
    """Detect surge of rate limit events."""
    name = "rate_limit_surge"
    severity = "medium"
    nist_controls = ["3.14.6"]

    def __init__(self, threshold: int = 50, window_seconds: int = 60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events):
        cutoff = datetime.now(timezone.utc) - self.window
        rl_events = [e for e in events
                     if e.action == "rate_limit_hit" and e.timestamp > cutoff]
        if len(rl_events) >= self.threshold:
            return SecurityIncident(
                title=f"Rate limit surge: {len(rl_events)} events in {self.window}",
                severity=self.severity,
                detected_by=self.name,
                nist_controls=self.nist_controls,
                events=rl_events,
            )
        return None


class CrossTenantAccess(CorrelationRule):
    """Detect users accessing data outside their opco/vessel."""
    name = "cross_tenant_access"
    severity = "critical"
    nist_controls = ["3.1.3"]

    def evaluate(self, events):
        for e in events:
            if (e.category == "access"
                and e.details.get("result") == "denied"
                and "cross_tenant" in str(e.details.get("failure_reason", ""))):
                return SecurityIncident(
                    title=f"Cross-tenant access attempt by {e.user_id}",
                    severity=self.severity,
                    detected_by=self.name,
                    nist_controls=self.nist_controls,
                    cui_involved=True,
                    events=[e],
                )
        return None


# Registry of all built-in rules
ALL_RULES = [
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
```

---

## Step 4: Run tests, commit

```bash
python -m pytest tests/test_correlator.py -v
git add -A
git commit -m "feat: correlation engine with 12 detection rules (NIST 3.14.6, 3.14.7)"
```
