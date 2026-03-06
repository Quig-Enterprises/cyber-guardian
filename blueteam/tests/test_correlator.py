"""Tests for correlation engine and rules."""
from datetime import datetime, timezone, timedelta
from blueteam.models import SecurityEvent, SecurityIncident
from blueteam.correlator.engine import CorrelationEngine
from blueteam.correlator.rules import (
    BruteForceDetection, CredentialStuffing, PrivilegeEscalation,
    AnomalousAccess, DataExfiltration, AIAbusePattern,
    AfterHoursAccess, AccountTakeover, SessionAnomaly,
    AuditLogGap, RateLimitSurge, CrossTenantAccess, ALL_RULES,
)

NOW = datetime.now(timezone.utc)
CONFIG = {"correlation": {"window_seconds": 300, "rules": {
    "brute_force": {"threshold": 3},
    "credential_stuffing": {"threshold": 3},
    "data_exfiltration": {"threshold": 3},
}}}


def _event(action="login", ip="1.2.3.4", user=None, severity="medium",
           category="auth", result="failure", cui=False, source="audit_db",
           details=None, ts=None):
    d = {"result": result}
    if details:
        d.update(details)
    return SecurityEvent(
        timestamp=ts or NOW,
        source=source,
        category=category,
        severity=severity,
        action=action,
        user_id=user,
        ip_address=ip,
        details=d,
        cui_involved=cui,
    )


def test_all_rules_registered():
    assert len(ALL_RULES) == 12


def test_engine_processes_events():
    engine = CorrelationEngine(CONFIG)
    engine.register_rule(BruteForceDetection())
    events = [_event(ip="10.0.0.1") for _ in range(3)]
    incidents = engine.process_events(events)
    assert len(incidents) == 1
    assert "10.0.0.1" in incidents[0].title


def test_engine_prunes_old_events():
    engine = CorrelationEngine({"correlation": {"window_seconds": 60}})
    engine.register_rule(BruteForceDetection())
    old = [_event(ip="10.0.0.1", ts=NOW - timedelta(seconds=120)) for _ in range(5)]
    engine.process_events(old)
    # Old events should be pruned — no incidents from fresh check
    new_engine = CorrelationEngine({"correlation": {"window_seconds": 60}})
    new_engine.register_rule(BruteForceDetection())
    incidents = new_engine.process_events(old)
    assert len(incidents) == 0


def test_brute_force_below_threshold():
    rule = BruteForceDetection()
    events = [_event(ip="1.2.3.4") for _ in range(2)]
    assert rule.evaluate(events, CONFIG) == []


def test_brute_force_at_threshold():
    rule = BruteForceDetection()
    events = [_event(ip="1.2.3.4") for _ in range(3)]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1
    assert incidents[0].severity == "high"


def test_brute_force_no_duplicate_alerts():
    rule = BruteForceDetection()
    events = [_event(ip="1.2.3.4") for _ in range(5)]
    rule.evaluate(events, CONFIG)
    # Second evaluation should not re-alert same IP
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 0


def test_credential_stuffing():
    rule = CredentialStuffing()
    events = [_event(ip="10.0.0.1", user=f"user{i}") for i in range(3)]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1
    assert incidents[0].severity == "critical"


def test_privilege_escalation():
    rule = PrivilegeEscalation()
    events = [_event(action="impersonation_start", user="admin1")]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1
    assert "impersonation_start" in incidents[0].title


def test_anomalous_access():
    rule = AnomalousAccess()
    events = [_event(action="forbidden_request", details={"path": "/api/admin/users", "result": "denied"})]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1
    assert incidents[0].nist_controls == ["3.1.1", "3.1.2"]


def test_data_exfiltration():
    rule = DataExfiltration()
    events = [_event(user="badactor", cui=True) for _ in range(3)]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1
    assert incidents[0].cui_involved


def test_ai_abuse():
    rule = AIAbusePattern()
    events = [_event(action="guardrail_triggered", user="user1") for _ in range(3)]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1
    assert "AI abuse" in incidents[0].title


def test_after_hours_admin():
    rule = AfterHoursAccess()
    late = NOW.replace(hour=23, minute=0)
    events = [_event(action="settings_change", category="admin", ts=late, user="admin1")]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1


def test_after_hours_normal_time():
    rule = AfterHoursAccess()
    normal = NOW.replace(hour=14, minute=0)
    events = [_event(action="settings_change", category="admin", ts=normal)]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 0


def test_account_takeover():
    rule = AccountTakeover()
    events = [
        _event(action="password_reset_sent", user="victim", ip="1.1.1.1",
               ts=NOW - timedelta(seconds=10)),
        _event(action="login", user="victim", ip="9.9.9.9", result="success", ts=NOW),
    ]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1
    assert incidents[0].severity == "critical"


def test_account_takeover_same_ip_no_alert():
    rule = AccountTakeover()
    events = [
        _event(action="password_reset_sent", user="user1", ip="1.1.1.1",
               ts=NOW - timedelta(seconds=10)),
        _event(action="login", user="user1", ip="1.1.1.1", result="success", ts=NOW),
    ]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 0


def test_session_anomaly():
    rule = SessionAnomaly()
    events = [
        _event(action="login", user="user1", ip=f"10.0.0.{i}", result="success")
        for i in range(3)
    ]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1


def test_audit_log_gap():
    rule = AuditLogGap()
    old_events = [_event(source="audit_db", ts=NOW - timedelta(minutes=20))]
    rule.evaluate(old_events, CONFIG)  # set baseline
    new_events = [_event(source="audit_db", ts=NOW)]
    incidents = rule.evaluate(new_events, CONFIG)
    assert len(incidents) == 1
    assert "gap" in incidents[0].title.lower()


def test_rate_limit_surge():
    rule = RateLimitSurge()
    events = [_event(action="rate_limit_hit", ip="5.5.5.5") for _ in range(5)]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1


def test_cross_tenant():
    rule = CrossTenantAccess()
    events = [_event(
        action="api_request", user="user1",
        details={"result": "denied", "resource_type": "instance_data", "resource_id": "inst-99"},
    )]
    incidents = rule.evaluate(events, CONFIG)
    assert len(incidents) == 1
    assert incidents[0].cui_involved
