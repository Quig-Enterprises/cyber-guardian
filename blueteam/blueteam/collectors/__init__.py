"""Collector registry — discovers and instantiates enabled collectors."""
from blueteam.collectors.base import BaseCollector
from blueteam.collectors.db_audit import DBAuditCollector
from blueteam.collectors.syslog_parser import SyslogCollector
from blueteam.collectors.nginx_log import NginxLogCollector
from blueteam.collectors.php_error import PHPErrorCollector
from blueteam.collectors.redteam_report import RedTeamCollector

ALL_COLLECTORS: list[type[BaseCollector]] = [
    DBAuditCollector,
    SyslogCollector,
    NginxLogCollector,
    PHPErrorCollector,
    RedTeamCollector,
]


def get_enabled_collectors(config: dict) -> list[BaseCollector]:
    """Return instantiated collectors that are enabled in config."""
    enabled = []
    collectors_cfg = config.get("collectors", {})
    for cls in ALL_COLLECTORS:
        if collectors_cfg.get(cls.name, {}).get("enabled", False):
            enabled.append(cls(config))
    return enabled
