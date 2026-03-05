"""Tests for incident manager and DFARS reporting."""
from blueteam.models import SecurityIncident
from blueteam.incidents.dfars import is_dfars_reportable


def test_create_incident_model():
    incident = SecurityIncident(
        title="Brute force from 1.2.3.4",
        severity="high",
        detected_by="brute_force",
        nist_controls=["3.1.8"],
    )
    assert incident.severity == "high"
    assert incident.cui_involved is False
    assert incident.title == "Brute force from 1.2.3.4"


def test_cui_incident_model():
    incident = SecurityIncident(
        title="Data exfiltration",
        severity="critical",
        detected_by="data_exfiltration",
        nist_controls=["3.1.3"],
        cui_involved=True,
    )
    assert incident.cui_involved is True


def test_dfars_reportable_cui_critical():
    assert is_dfars_reportable(cui_involved=True, severity="critical")


def test_dfars_reportable_cui_high():
    assert is_dfars_reportable(cui_involved=True, severity="high")


def test_dfars_not_reportable_cui_medium():
    assert not is_dfars_reportable(cui_involved=True, severity="medium")


def test_dfars_not_reportable_no_cui():
    assert not is_dfars_reportable(cui_involved=False, severity="critical")


def test_dfars_not_reportable_low():
    assert not is_dfars_reportable(cui_involved=False, severity="low")
