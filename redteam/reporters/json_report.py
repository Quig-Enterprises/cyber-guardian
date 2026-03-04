"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path


class JsonReporter:
    def write_report(self, summary: dict, output_dir: str) -> str:
        """Write JSON report. Returns file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(output_dir) / f"redteam-report-{timestamp}.json"

        report = {
            "generated": datetime.now().isoformat(),
            "total_attacks": summary["total_attacks"],
            "total_variants": summary["total_variants"],
            "total_vulnerable": summary["total_vulnerable"],
            "total_partial": summary["total_partial"],
            "total_defended": summary["total_defended"],
            "total_errors": summary["total_errors"],
            "worst_severity": summary["worst_severity"].value,
            "by_category": summary["by_category"],
            "by_severity": summary["by_severity"],
            "findings": [],
        }

        for score in summary["scores"]:
            for r in score.results:
                report["findings"].append({
                    "attack": r.attack_name,
                    "variant": r.variant,
                    "status": r.status.value,
                    "severity": r.severity.value,
                    "evidence": r.evidence,
                    "details": r.details,
                    "request": r.request,
                    "response": r.response,
                    "duration_ms": r.duration_ms,
                })

        path.write_text(json.dumps(report, indent=2, default=str))
        return str(path)
