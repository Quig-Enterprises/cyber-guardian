"""Import red team attack results for posture scoring."""
import json
from pathlib import Path
from datetime import datetime, timezone
from blueteam.db import get_connection


def import_report(config: dict, report_path: str) -> dict:
    """Import a red team JSON report into posture scoring."""
    path = Path(report_path)
    with open(path) as f:
        report = json.load(f)

    summary = report.get("summary", {})
    attacks = report.get("attacks", [])

    total = summary.get("total_variants", 0)
    defended = summary.get("defended", 0)
    partial = summary.get("partial", 0)
    vulnerable = summary.get("vulnerable", 0)

    # If no summary, calculate from attacks
    if total == 0 and attacks:
        for attack in attacks:
            for variant in attack.get("variants", []):
                total += 1
                result = variant.get("result", "")
                if result == "safe":
                    defended += 1
                elif result == "partial":
                    partial += 1
                elif result == "vulnerable":
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
