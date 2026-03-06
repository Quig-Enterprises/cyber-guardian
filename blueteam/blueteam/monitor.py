"""Real-time security monitoring daemon."""
import time
import signal
from datetime import datetime, timezone
from rich.console import Console

from blueteam.collectors import get_enabled_collectors
from blueteam.correlator.engine import CorrelationEngine
from blueteam.correlator.rules import ALL_RULES
from blueteam.alerting.engine import AlertEngine

console = Console()


class MonitorDaemon:
    """Main monitoring loop: collect -> correlate -> alert."""

    def __init__(self, config: dict):
        self.config = config
        self.running = False
        self.poll_interval = config.get("monitoring", {}).get("poll_interval_sec", 5)

        # Initialize subsystems
        self.collectors = get_enabled_collectors(config)
        self.correlator = CorrelationEngine(config)
        self.alert_engine = AlertEngine(config)

        # Register all correlation rules
        for rule_cls in ALL_RULES:
            self.correlator.register_rule(rule_cls())

        # Stats
        self.stats = {
            "events_collected": 0,
            "incidents_detected": 0,
            "alerts_sent": 0,
            "started_at": None,
            "last_poll": None,
        }

    def start(self):
        """Start the monitoring loop."""
        self.running = True
        self.stats["started_at"] = datetime.now(timezone.utc)
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        console.print("[bold green]Blue Team Monitor Started[/bold green]")
        console.print(f"  Collectors: {len(self.collectors)} enabled")
        console.print(f"  Rules: {len(self.correlator._rules)} active")
        console.print(f"  Poll interval: {self.poll_interval}s")
        console.print("  Press Ctrl+C to stop\n")

        while self.running:
            try:
                self._poll_cycle()
                time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                break

        console.print("\n[bold yellow]Monitor stopped.[/bold yellow]")
        self._print_stats()

    def _poll_cycle(self):
        """Single poll cycle: collect from all sources, correlate, alert."""
        all_events = []
        for collector in self.collectors:
            try:
                events = collector.collect()
                all_events.extend(events)
            except Exception as e:
                console.print(f"[red]Collector {collector.name} error: {e}[/red]")

        self.stats["events_collected"] += len(all_events)
        self.stats["last_poll"] = datetime.now(timezone.utc)

        if all_events:
            incidents = self.correlator.process_events(all_events)
            for incident in incidents:
                self.stats["incidents_detected"] += 1
                sent = self.alert_engine.alert(incident)
                self.stats["alerts_sent"] += sent

    def _shutdown(self, signum, frame):
        self.running = False

    def _print_stats(self):
        uptime = datetime.now(timezone.utc) - self.stats["started_at"]
        console.print("\n[bold]Session Summary:[/bold]")
        console.print(f"  Uptime: {uptime}")
        console.print(f"  Events collected: {self.stats['events_collected']}")
        console.print(f"  Incidents detected: {self.stats['incidents_detected']}")
        console.print(f"  Alerts sent: {self.stats['alerts_sent']}")
