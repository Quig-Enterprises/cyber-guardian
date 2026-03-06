"""Import red team attack results for posture scoring."""
import json
from pathlib import Path
from datetime import datetime, timezone
from shared import get_connection


def import_report(config: dict, report_path: str) -> dict:
    """Import a red team JSON report into posture scoring."""
    path = Path(report_path)
    with open(path) as f:
        report = json.load(f)

    # Support both formats:
    #   1. Wrapped: report["summary"]["total_variants"], report["attacks"][*]["variants"]
    #   2. Flat:    report["total_variants"], report["findings"]
    summary = report.get("summary", {})
    attacks = report.get("attacks", [])

    total = summary.get("total_variants", 0) or report.get("total_variants", 0)
    defended = summary.get("defended", 0) or report.get("total_defended", 0)
    partial = summary.get("partial", 0) or report.get("total_partial", 0)
    vulnerable = summary.get("vulnerable", 0) or report.get("total_vulnerable", 0)

    # If still no totals, calculate from attacks/findings
    if total == 0:
        findings = attacks or report.get("findings", [])
        for attack in findings:
            for variant in attack.get("variants", attack.get("results", [])):
                total += 1
                result = variant.get("result", variant.get("status", ""))
                if result in ("safe", "defended", "DEFENDED"):
                    defended += 1
                elif result in ("partial", "PARTIAL"):
                    partial += 1
                elif result in ("vulnerable", "VULNERABLE"):
                    vulnerable += 1

    # Calculate red team score (0-100, higher = better defended)
    if total > 0:
        score = ((defended * 1.0 + partial * 0.5) / total) * 100
    else:
        score = 0

    # Store posture score
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO blueteam.posture_scores
                (redteam_score, details, redteam_report_id)
            VALUES (%s, %s, %s)
            RETURNING score_id
        """, (round(score, 2), json.dumps({
            "total_variants": total,
            "defended": defended,
            "partial": partial,
            "vulnerable": vulnerable,
            "report_file": path.name,
            "imported_at": datetime.now(timezone.utc).isoformat(),
        }), path.stem))
        row = cur.fetchone()

    return {
        "score_id": str(row["score_id"]),
        "redteam_score": round(score, 2),
        "total": total,
        "defended": defended,
        "partial": partial,
        "vulnerable": vulnerable,
    }
