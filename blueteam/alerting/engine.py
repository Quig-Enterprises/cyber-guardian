"""Alert engine — routes incidents to appropriate channels based on severity."""
import logging
from blueteam.models import SecurityIncident
from blueteam.alerting.channels import SyslogChannel, EmailChannel, ConsoleChannel

logger = logging.getLogger(__name__)


class AlertEngine:
    """Routes security incidents to alert channels based on severity."""

    # Minimum severity for each channel
    SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
    CHANNEL_THRESHOLDS = {
        "syslog": "low",       # All events except info
        "email": "high",       # Only high and critical
        "console": "info",     # Everything (dev mode)
    }

    def __init__(self, config: dict):
        self.config = config
        self._channels = []
        alerting_cfg = config.get("alerting", {})

        if alerting_cfg.get("syslog", {}).get("enabled", False):
            self._channels.append(("syslog", SyslogChannel(config)))

        if alerting_cfg.get("email", {}).get("enabled", False):
            self._channels.append(("email", EmailChannel(config)))

        # Console always available but only used in verbose mode
        self._console = ConsoleChannel(config)
        self._verbose = config.get("monitoring", {}).get("verbose", False)

    def alert(self, incident: SecurityIncident) -> int:
        """Send incident to all qualifying channels. Returns count of successful sends."""
        sent = 0
        sev_idx = self._severity_index(incident.severity)

        for name, channel in self._channels:
            threshold = self.CHANNEL_THRESHOLDS.get(name, "low")
            if sev_idx >= self._severity_index(threshold):
                try:
                    if channel.send(incident):
                        sent += 1
                except Exception as e:
                    logger.error("Channel %s failed: %s", name, e)

        # CUI incidents always go to all channels regardless of threshold
        if incident.cui_involved:
            for name, channel in self._channels:
                threshold = self.CHANNEL_THRESHOLDS.get(name, "low")
                if sev_idx < self._severity_index(threshold):
                    try:
                        channel.send(incident)
                        sent += 1
                    except Exception as e:
                        logger.error("CUI escalation to %s failed: %s", name, e)

        if self._verbose:
            self._console.send(incident)

        return sent

    def alert_many(self, incidents: list[SecurityIncident]) -> int:
        """Send multiple incidents. Returns total successful sends."""
        total = 0
        for incident in incidents:
            total += self.alert(incident)
        return total

    def _severity_index(self, severity: str) -> int:
        try:
            return self.SEVERITY_ORDER.index(severity.lower())
        except ValueError:
            return 2  # default to medium
