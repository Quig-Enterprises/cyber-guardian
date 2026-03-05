"""Tests for collector modules."""
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock
from blueteam.collectors import get_enabled_collectors, ALL_COLLECTORS
from blueteam.collectors.base import BaseCollector
from blueteam.collectors.nginx_log import NginxLogCollector
from blueteam.collectors.php_error import PHPErrorCollector
from blueteam.collectors.syslog_parser import SyslogCollector
from blueteam.collectors.redteam_report import RedTeamCollector


BASE_CONFIG = {
    "database": {"host": "localhost", "name": "test", "user": "test"},
    "collectors": {
        "db_audit": {"enabled": True},
        "syslog": {"enabled": True, "path": "/dev/null"},
        "nginx": {"enabled": True, "path": "/dev/null"},
        "php_errors": {"enabled": True, "paths": []},
        "redteam": {"enabled": False, "reports_dir": "/tmp/nonexistent"},
    },
}


def test_all_collectors_registered():
    assert len(ALL_COLLECTORS) == 5


def test_get_enabled_collectors_filters():
    collectors = get_enabled_collectors(BASE_CONFIG)
    names = [c.name for c in collectors]
    assert "redteam" not in names
    assert "db_audit" in names
    assert "syslog" in names
    assert "nginx" in names


def test_nginx_parses_4xx():
    config = {**BASE_CONFIG, "collectors": {"nginx": {"path": "/dev/null"}}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write('192.168.1.1 - - [05/Mar/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0\n')
        f.write('10.0.0.1 - - [05/Mar/2026:10:00:01 +0000] "GET /api/status HTTP/1.1" 200 100\n')
        f.write('10.0.0.2 - - [05/Mar/2026:10:00:02 +0000] "POST /api/login HTTP/1.1" 401 50\n')
        f.flush()
        config["collectors"]["nginx"]["path"] = f.name

    collector = NginxLogCollector(config)
    events = collector.collect()
    assert len(events) == 2  # 404 and 401, not 200
    assert events[0].action == "recon_probe"
    assert events[0].severity == "high"
    assert events[1].action == "unauthorized_request"


def test_nginx_skips_ok_responses():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write('10.0.0.1 - - [05/Mar/2026:10:00:00 +0000] "GET /api/health HTTP/1.1" 200 50\n')
        f.flush()
        config = {**BASE_CONFIG}
        config["collectors"] = {"nginx": {"path": f.name}}

    collector = NginxLogCollector(config)
    events = collector.collect()
    assert len(events) == 0


def test_php_error_json_format():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(json.dumps({"level": "FATAL", "message": "Undefined var", "file": "test.php"}) + "\n")
        f.flush()
        config = {**BASE_CONFIG}
        config["collectors"] = {"php_errors": {"paths": [f.name]}}

    collector = PHPErrorCollector(config)
    events = collector.collect()
    assert len(events) == 1
    assert events[0].severity == "high"
    assert events[0].details["level"] == "FATAL"


def test_php_error_plain_text():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("Fatal error: allowed memory in /var/www/test.php on line 42\n")
        f.flush()
        config = {**BASE_CONFIG}
        config["collectors"] = {"php_errors": {"paths": [f.name]}}

    collector = PHPErrorCollector(config)
    events = collector.collect()
    assert len(events) == 1
    assert events[0].action == "php_fatal_error"


def test_syslog_parses_auth_patterns():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("Mar  5 10:00:00 artemis eqmon-auth: Forgot password rate limited email=test@x.com ip=1.2.3.4\n")
        f.flush()
        config = {**BASE_CONFIG}
        config["collectors"] = {"syslog": {"path": f.name}}

    collector = SyslogCollector(config)
    events = collector.collect()
    assert len(events) == 1
    assert events[0].action == "password_reset_rate_limited"
    assert events[0].severity == "high"


def test_redteam_imports_reports():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = {
            "attacks": [{
                "name": "sql_injection",
                "category": "api",
                "variants": [
                    {"name": "basic", "result": "vulnerable", "severity": "high", "confidence": 0.95, "nist_controls": ["3.14.1"]},
                    {"name": "blind", "result": "safe", "severity": "high", "confidence": 0.9, "nist_controls": ["3.14.1"]},
                ],
            }],
        }
        Path(tmpdir, "report_001.json").write_text(json.dumps(report))
        config = {**BASE_CONFIG}
        config["collectors"] = {"redteam": {"reports_dir": tmpdir}}

        collector = RedTeamCollector(config)
        events = collector.collect()
        assert len(events) == 1  # only "vulnerable", not "safe"
        assert events[0].details["attack"] == "sql_injection"
        assert events[0].details["variant"] == "basic"


def test_redteam_skips_already_imported():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = {"attacks": [{"name": "xss", "category": "web",
                               "variants": [{"name": "reflected", "result": "vulnerable", "severity": "medium"}]}]}
        Path(tmpdir, "report_002.json").write_text(json.dumps(report))
        config = {**BASE_CONFIG}
        config["collectors"] = {"redteam": {"reports_dir": tmpdir}}

        collector = RedTeamCollector(config)
        events1 = collector.collect()
        events2 = collector.collect()
        assert len(events1) == 1
        assert len(events2) == 0  # already imported


def test_collector_incremental_read():
    """Verify file-based collectors track position and don't re-read."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write('10.0.0.1 - - [05/Mar/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 403 0\n')
        f.flush()
        config = {**BASE_CONFIG}
        config["collectors"] = {"nginx": {"path": f.name}}

        collector = NginxLogCollector(config)
        events1 = collector.collect()
        assert len(events1) == 1

        # Write more data
        f.write('10.0.0.2 - - [05/Mar/2026:10:00:01 +0000] "GET /secret HTTP/1.1" 403 0\n')
        f.flush()

        events2 = collector.collect()
        assert len(events2) == 1  # only the new line
        assert events2[0].ip_address == "10.0.0.2"
