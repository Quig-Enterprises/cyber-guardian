"""Test hierarchical JSON reporter implementation."""

import json
from datetime import datetime
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from redteam.base import AttackResult, Score, Severity, Status
from redteam.reporters.hierarchical_json import HierarchicalJsonReporter
from redteam.scoring import aggregate_scores


def create_sample_results() -> list[Score]:
    """Create sample attack results for testing."""
    # Create sample attack results
    results1 = [
        AttackResult(
            attack_name="api.account_lockout_bypass",
            variant="rapid_attempts",
            status=Status.VULNERABLE,
            severity=Severity.MEDIUM,
            evidence="All 10 rapid login failures completed in 0.0s without lockout",
            details="No rate limiting detected. Brute-force attacks possible.",
            request={
                "endpoint": "/api/auth/login.php",
                "method": "POST",
                "attempts": 10,
                "target_email": "redteam-sysadmin@example.com"
            },
            response={
                "status_codes": [404] * 10,
                "lockout_headers": None,
                "lockout_triggered": False,
            },
            duration_ms=20.0,
        ),
        AttackResult(
            attack_name="api.account_lockout_bypass",
            variant="ip_rotation",
            status=Status.PARTIAL,
            severity=Severity.MEDIUM,
            evidence="Lockout triggered but can be bypassed with IP rotation",
            details="Account lockout works but is IP-based only",
            request={
                "endpoint": "/api/auth/login.php",
                "method": "POST",
                "attempts": 15,
            },
            response={
                "status_codes": [404] * 15,
                "lockout_triggered": True,
            },
            duration_ms=30.0,
        ),
        AttackResult(
            attack_name="api.account_lockout_bypass",
            variant="rate_limit_header_check",
            status=Status.DEFENDED,
            severity=Severity.MEDIUM,
            evidence="Rate limiting headers present and enforced",
            details="X-RateLimit headers indicate proper rate limiting",
            request={"method": "POST"},
            response={"status_codes": [429], "rate_limit_headers": {"X-RateLimit-Remaining": "0"}},
            duration_ms=10.0,
        ),
    ]

    results2 = [
        AttackResult(
            attack_name="api.auth_bypass",
            variant="jwt_none_alg",
            status=Status.VULNERABLE,
            severity=Severity.CRITICAL,
            evidence="JWT with 'none' algorithm accepted",
            details="Server accepts unsigned JWTs with alg=none",
            request={"jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0..."},
            response={"status_code": 200, "authenticated": True},
            duration_ms=15.0,
        ),
        AttackResult(
            attack_name="api.auth_bypass",
            variant="weak_secret",
            status=Status.DEFENDED,
            severity=Severity.CRITICAL,
            evidence="Strong JWT secret detected",
            details="Unable to crack JWT signature",
            request={},
            response={},
            duration_ms=100.0,
        ),
    ]

    # Create Score objects
    score1 = Score(
        attack_name="api.account_lockout_bypass",
        category="api",
        total_variants=3,
        results=results1,
        duration_ms=60.0,
    )
    score1.vulnerable = 1
    score1.partial = 1
    score1.defended = 1
    score1.worst_severity = Severity.MEDIUM

    score2 = Score(
        attack_name="api.auth_bypass",
        category="api",
        total_variants=2,
        results=results2,
        duration_ms=115.0,
    )
    score2.vulnerable = 1
    score2.defended = 1
    score2.worst_severity = Severity.CRITICAL

    return [score1, score2]


def test_hierarchical_reporter():
    """Test the hierarchical JSON reporter."""
    print("Testing HierarchicalJsonReporter...")

    # Create sample data
    scores = create_sample_results()
    summary = aggregate_scores(scores)

    # Configure reporter
    config = {
        "target": {
            "base_url": "https://keystone.quigs.com",
            "name": "Project Keystone",
            "environment": "production",
            "type": "app",
        },
        "execution": {
            "mode": "full",
            "start_time": "2026-03-08T18:43:15.000000",
            "scanner_version": "1.0.0",
            "rate_limit_testing": True,
            "rate_limit_test_ip": "203.0.113.99",
        },
        "cleanup": {
            "enabled": True,
        },
        "ai_attacker": {
            "enabled": True,
            "attacker_model": "claude-sonnet-4-6",
            "judge_model": "claude-haiku-4-5-20251001",
        },
    }

    # Generate report
    reporter = HierarchicalJsonReporter(config)
    output_dir = Path(__file__).parent.parent / "reports"
    output_dir.mkdir(exist_ok=True)

    report_path = reporter.write_report(summary, str(output_dir))
    print(f"✓ Report generated: {report_path}")

    # Verify report structure
    with open(report_path) as f:
        report = json.load(f)

    # Check top-level structure
    required_keys = ["scan_metadata", "summary", "attacks", "scan_config", "findings"]
    for key in required_keys:
        assert key in report, f"Missing required key: {key}"
        print(f"✓ Found required key: {key}")

    # Check scan_metadata structure
    metadata = report["scan_metadata"]
    assert "scan_id" in metadata
    assert metadata["scan_id"].startswith("scan-")
    print(f"✓ Scan ID: {metadata['scan_id']}")

    assert metadata["target"]["url"] == "https://keystone.quigs.com"
    assert metadata["target"]["name"] == "Project Keystone"
    assert metadata["target"]["environment"] == "production"
    assert metadata["execution"]["mode"] == "full"
    print("✓ Target and execution metadata correct")

    # Check summary structure
    summary_data = report["summary"]
    assert summary_data["attacks_executed"] == 2
    assert summary_data["variants_tested"] == 5
    assert summary_data["findings"]["vulnerable"] == 2
    assert summary_data["findings"]["partial"] == 1
    assert summary_data["findings"]["defended"] == 2
    print("✓ Summary statistics correct")

    # Check hierarchical attacks structure
    attacks = report["attacks"]
    assert len(attacks) == 2
    print(f"✓ Found {len(attacks)} attacks")

    # Check first attack
    attack1 = attacks[0]
    assert attack1["attack_id"] == "api.account_lockout_bypass"
    assert attack1["category"] == "api"
    assert len(attack1["variants"]) == 3
    print(f"✓ Attack 1 has {len(attack1['variants'])} variants")

    # Check variant structure
    variant1 = attack1["variants"][0]
    required_variant_keys = [
        "variant_id", "name", "status", "severity", "duration_ms",
        "evidence", "request", "response", "recommendation"
    ]
    for key in required_variant_keys:
        assert key in variant1, f"Missing variant key: {key}"
    print("✓ Variant structure complete")

    # Check evidence structure
    evidence = variant1["evidence"]
    assert "summary" in evidence
    assert "technical_details" in evidence
    assert "proof" in evidence
    print("✓ Evidence structure correct")

    # Check recommendation structure
    recommendation = variant1["recommendation"]
    assert "priority" in recommendation
    assert "remediation" in recommendation
    assert "references" in recommendation
    print("✓ Recommendation structure correct")

    # Check scan_config structure
    scan_config = report["scan_config"]
    assert scan_config["execution_mode"] == "full"
    assert scan_config["rate_limit_testing"] is True
    assert scan_config["ai_attacker_enabled"] is True
    print("✓ Scan config captured")

    # Check backward-compatible findings array
    findings = report["findings"]
    assert len(findings) == 5  # Total variants
    assert findings[0]["attack"] == "api.account_lockout_bypass"
    assert findings[0]["variant"] == "rapid_attempts"
    print("✓ Backward-compatible findings array present")

    print("\n✓ All tests passed!")
    print(f"\nReport location: {report_path}")
    print(f"Report size: {Path(report_path).stat().st_size} bytes")

    # Print sample of report structure
    print("\nSample report structure:")
    print(json.dumps({
        "scan_metadata": {
            "scan_id": report["scan_metadata"]["scan_id"],
            "target": report["scan_metadata"]["target"],
        },
        "summary": {
            "attacks_executed": report["summary"]["attacks_executed"],
            "variants_tested": report["summary"]["variants_tested"],
            "findings": report["summary"]["findings"],
        },
        "attacks_count": len(report["attacks"]),
        "first_attack": {
            "attack_id": report["attacks"][0]["attack_id"],
            "variants_count": len(report["attacks"][0]["variants"]),
        },
    }, indent=2))


if __name__ == "__main__":
    test_hierarchical_reporter()
