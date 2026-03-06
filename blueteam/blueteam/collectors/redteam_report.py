"""Red team report collector — imports attack results for posture scoring."""
import json
from datetime import datetime, timezone
from pathlib import Path
from blueteam.collectors.base import BaseCollector
from blueteam.models import SecurityEvent


class RedTeamCollector(BaseCollector):
    name = "redteam"

    def __init__(self, config: dict):
        super().__init__(config)
        reports_dir = config.get("collectors", {}).get("redteam", {}).get(
            "reports_dir", "/opt/security-red-team/reports"
        )
        self._reports_dir = Path(reports_dir)
        self._imported_files = set()

    def collect(self) -> list[SecurityEvent]:
        if not self._reports_dir.exists():
            return []

        events = []
        for report_file in sorted(self._reports_dir.glob("*.json")):
            if report_file.name in self._imported_files:
                continue
            self._imported_files.add(report_file.name)

            try:
                with open(report_file) as f:
                    report = json.load(f)

                for attack in report.get("attacks", []):
                    for variant in attack.get("variants", []):
                        if variant.get("result") in ("vulnerable", "partial"):
                            events.append(SecurityEvent(
                                timestamp=datetime.now(timezone.utc),
                                source="redteam",
                                category="system",
                                severity=variant.get("severity", "medium").lower(),
                                action=f"redteam_{variant.get('result', 'unknown')}",
                                details={
                                    "attack": attack.get("name"),
                                    "variant": variant.get("name"),
                                    "category": attack.get("category"),
                                    "confidence": variant.get("confidence"),
                                    "report_file": report_file.name,
                                },
                                nist_controls=variant.get("nist_controls", []),
                            ))
            except (json.JSONDecodeError, KeyError):
                pass

        return events
