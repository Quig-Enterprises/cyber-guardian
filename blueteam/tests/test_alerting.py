"""Tests for alerting engine and channels."""
from unittest.mock import patch, MagicMock
from blueteam.models import SecurityIncident
from blueteam.alerting.engine import AlertEngine
from blueteam.alerting.channels import SyslogChannel, EmailChannel, ConsoleChannel


CONFIG = {
    "alerting": {
        "syslog": {"enabled": True, "facility": "local6"},
        "email": {"enabled": False},
    },
    "monitoring": {"verbose": False},
}


def _incident(severity="high", cui=False, title="Test incident"):
    return SecurityIncident(
        title=title,
        severity=severity,
        detected_by="test_rule",
        nist_controls=["3.3.1"],
        description="Test",
        cui_involved=cui,
    )


@patch("blueteam.alerting.channels.syslog")
def test_syslog_channel_sends(mock_syslog):
    channel = SyslogChannel(CONFIG)
    result = channel.send(_incident())
    assert result is True
    mock_syslog.syslog.assert_called_once()
    call_msg = mock_syslog.syslog.call_args[0][1]
    assert "SECURITY_INCIDENT" in call_msg
    assert "severity=high" in call_msg


@patch("blueteam.alerting.channels.syslog")
def test_syslog_cui_tag(mock_syslog):
    channel = SyslogChannel(CONFIG)
    channel.send(_incident(cui=True))
    call_msg = mock_syslog.syslog.call_args[0][1]
    assert "[CUI]" in call_msg


def test_console_channel():
    channel = ConsoleChannel(CONFIG)
    result = channel.send(_incident())
    assert result is True


def test_console_channel_cui(capsys):
    channel = ConsoleChannel(CONFIG)
    channel.send(_incident(cui=True))
    output = capsys.readouterr().out
    assert "[CUI]" in output


@patch("blueteam.alerting.channels.smtplib.SMTP")
def test_email_channel_sends(mock_smtp):
    email_config = {
        "alerting": {"email": {
            "smtp_host": "localhost", "smtp_port": 587,
            "from_address": "test@x.com", "recipients": ["admin@x.com"],
        }},
    }
    channel = EmailChannel(email_config)
    result = channel.send(_incident())
    assert result is True
    mock_smtp.return_value.__enter__.return_value.sendmail.assert_called_once()


def test_email_channel_no_recipients():
    config = {"alerting": {"email": {"recipients": []}}}
    channel = EmailChannel(config)
    result = channel.send(_incident())
    assert result is False


@patch("blueteam.alerting.channels.syslog")
def test_alert_engine_routes_by_severity(mock_syslog):
    engine = AlertEngine(CONFIG)
    # Low severity should still go to syslog (threshold is "low")
    sent = engine.alert(_incident(severity="low"))
    assert sent >= 1

    # Info should NOT go to syslog (below "low" threshold)
    mock_syslog.reset_mock()
    engine2 = AlertEngine(CONFIG)
    sent = engine2.alert(_incident(severity="info"))
    assert sent == 0


@patch("blueteam.alerting.channels.syslog")
def test_alert_engine_cui_escalation(mock_syslog):
    """CUI incidents should go to all channels regardless of severity threshold."""
    engine = AlertEngine(CONFIG)
    sent = engine.alert(_incident(severity="info", cui=True))
    # Info normally wouldn't go to syslog, but CUI escalation forces it
    assert sent >= 1


@patch("blueteam.alerting.channels.syslog")
def test_alert_many(mock_syslog):
    engine = AlertEngine(CONFIG)
    incidents = [_incident() for _ in range(3)]
    total = engine.alert_many(incidents)
    assert total == 3


def test_severity_index():
    engine = AlertEngine(CONFIG)
    assert engine._severity_index("critical") > engine._severity_index("high")
    assert engine._severity_index("high") > engine._severity_index("medium")
    assert engine._severity_index("medium") > engine._severity_index("low")
    assert engine._severity_index("low") > engine._severity_index("info")
    # Unknown defaults to medium
    assert engine._severity_index("unknown") == engine._severity_index("medium")
