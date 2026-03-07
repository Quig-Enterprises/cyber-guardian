#!/usr/bin/env python3
"""CLI for Blue Team Codebase Security Scanner

Scans all projects on the server for security issues.
"""

import sys
import os
import json
from datetime import datetime
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from blueteam.api.codebase_scanner import get_scanner, Severity


def print_summary(results):
    """Print summary of scan results."""
    total_files = sum(r.files_scanned for r in results)
    total_issues = sum(len(r.issues) for r in results)
    critical = sum(r.critical_count for r in results)
    high = sum(r.high_count for r in results)
    medium = sum(r.medium_count for r in results)
    low = sum(r.low_count for r in results)

    print("\n" + "=" * 80)
    print("CODEBASE SECURITY SCAN SUMMARY")
    print("=" * 80)
    print(f"\nProjects scanned: {len(results)}")
    print(f"Files scanned: {total_files}")
    print(f"Total issues found: {total_issues}")
    print(f"\nSeverity breakdown:")
    print(f"  🔴 CRITICAL: {critical}")
    print(f"  🟠 HIGH:     {high}")
    print(f"  🟡 MEDIUM:   {medium}")
    print(f"  🔵 LOW:      {low}")


def print_issues_by_category(results):
    """Print issues grouped by category."""
    # Collect all issues
    all_issues = []
    for result in results:
        all_issues.extend(result.issues)

    # Group by category
    by_category = {}
    for issue in all_issues:
        if issue.category not in by_category:
            by_category[issue.category] = []
        by_category[issue.category].append(issue)

    print("\n" + "=" * 80)
    print("ISSUES BY CATEGORY")
    print("=" * 80)

    for category, issues in sorted(by_category.items(), key=lambda x: len(x[1]), reverse=True):
        critical = sum(1 for i in issues if i.severity == Severity.CRITICAL)
        high = sum(1 for i in issues if i.severity == Severity.HIGH)

        print(f"\n{category.upper().replace('_', ' ')} ({len(issues)} issues)")
        print(f"  CRITICAL: {critical}, HIGH: {high}")
        print(f"\n  Top occurrences:")

        # Show top 5 files with this issue
        for issue in sorted(issues, key=lambda x: x.severity.value)[:5]:
            print(f"    {issue.severity.value.upper()}: {issue.file_path}:{issue.line_number}")
            print(f"      {issue.code_snippet[:80]}...")


def print_top_projects(results, limit=10):
    """Print projects with most issues."""
    print("\n" + "=" * 80)
    print(f"TOP {limit} PROJECTS BY ISSUE COUNT")
    print("=" * 80)

    sorted_results = sorted(results, key=lambda r: len(r.issues), reverse=True)[:limit]

    for i, result in enumerate(sorted_results, 1):
        print(f"\n{i}. {result.project_name} ({len(result.issues)} issues)")
        print(f"   Path: {result.project_path}")
        print(f"   CRITICAL: {result.critical_count}, HIGH: {result.high_count}, "
              f"MEDIUM: {result.medium_count}, LOW: {result.low_count}")

        # Show critical issues
        critical_issues = [i for i in result.issues if i.severity == Severity.CRITICAL]
        if critical_issues:
            print(f"\n   Critical issues:")
            for issue in critical_issues[:3]:
                print(f"     - {issue.issue_type}")
                print(f"       {issue.file_path}:{issue.line_number}")
                print(f"       {issue.recommendation}")


def generate_json_report(results, output_path):
    """Generate JSON report file."""
    report = {
        "generated": datetime.now().isoformat(),
        "summary": {
            "projects_scanned": len(results),
            "total_files": sum(r.files_scanned for r in results),
            "total_issues": sum(len(r.issues) for r in results),
            "critical": sum(r.critical_count for r in results),
            "high": sum(r.high_count for r in results),
            "medium": sum(r.medium_count for r in results),
            "low": sum(r.low_count for r in results),
        },
        "projects": []
    }

    for result in results:
        project_data = {
            "name": result.project_name,
            "path": result.project_path,
            "files_scanned": result.files_scanned,
            "scan_duration_ms": result.scan_duration_ms,
            "issue_count": len(result.issues),
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "medium_count": result.medium_count,
            "low_count": result.low_count,
            "issues": []
        }

        for issue in result.issues:
            issue_data = {
                "severity": issue.severity.value,
                "category": issue.category,
                "file": issue.file_path,
                "line": issue.line_number,
                "type": issue.issue_type,
                "description": issue.description,
                "code_snippet": issue.code_snippet,
                "recommendation": issue.recommendation,
                "cwe_id": issue.cwe_id,
                "confidence": issue.confidence
            }
            project_data["issues"].append(issue_data)

        report["projects"].append(project_data)

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n✓ JSON report saved to: {output_path}")


def generate_markdown_report(results, output_path):
    """Generate Markdown report file."""
    total_files = sum(r.files_scanned for r in results)
    total_issues = sum(len(r.issues) for r in results)
    critical = sum(r.critical_count for r in results)
    high = sum(r.high_count for r in results)
    medium = sum(r.medium_count for r in results)
    low = sum(r.low_count for r in results)

    md = [
        "# Codebase Security Scan Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Projects Scanned** | {len(results)} |",
        f"| **Files Scanned** | {total_files} |",
        f"| **Total Issues** | {total_issues} |",
        f"| **CRITICAL** | {critical} |",
        f"| **HIGH** | {high} |",
        f"| **MEDIUM** | {medium} |",
        f"| **LOW** | {low} |",
        "",
        "---",
        "",
        "## Critical Findings",
        ""
    ]

    # List all critical issues
    critical_issues = []
    for result in results:
        critical_issues.extend([i for i in result.issues if i.severity == Severity.CRITICAL])

    if critical_issues:
        md.append(f"### {len(critical_issues)} Critical Issues Require Immediate Attention")
        md.append("")

        for i, issue in enumerate(critical_issues, 1):
            md.append(f"#### {i}. {issue.issue_type}")
            md.append("")
            md.append(f"**File:** `{issue.file_path}:{issue.line_number}`")
            md.append(f"**CWE:** {issue.cwe_id or 'N/A'}")
            md.append(f"**Confidence:** {issue.confidence.upper()}")
            md.append("")
            md.append("**Description:**")
            md.append(f"{issue.description}")
            md.append("")
            md.append("**Code:**")
            md.append("```php")
            md.append(issue.code_snippet)
            md.append("```")
            md.append("")
            md.append("**Recommendation:**")
            md.append(f"{issue.recommendation}")
            md.append("")
            md.append("---")
            md.append("")
    else:
        md.append("✅ No critical issues found!")
        md.append("")

    # Projects summary
    md.append("## Projects Summary")
    md.append("")
    md.append("| Project | Files | Issues | CRITICAL | HIGH | MEDIUM | LOW |")
    md.append("|---------|-------|--------|----------|------|--------|-----|")

    for result in sorted(results, key=lambda r: len(r.issues), reverse=True):
        md.append(f"| {result.project_name} | {result.files_scanned} | {len(result.issues)} | "
                  f"{result.critical_count} | {result.high_count} | {result.medium_count} | {result.low_count} |")

    md.append("")

    # Issues by category
    all_issues = []
    for result in results:
        all_issues.extend(result.issues)

    by_category = {}
    for issue in all_issues:
        if issue.category not in by_category:
            by_category[issue.category] = []
        by_category[issue.category].append(issue)

    md.append("## Issues by Category")
    md.append("")

    for category, issues in sorted(by_category.items(), key=lambda x: len(x[1]), reverse=True):
        critical_count = sum(1 for i in issues if i.severity == Severity.CRITICAL)
        high_count = sum(1 for i in issues if i.severity == Severity.HIGH)

        md.append(f"### {category.upper().replace('_', ' ')} ({len(issues)} issues)")
        md.append("")
        md.append(f"**CRITICAL:** {critical_count}, **HIGH:** {high_count}")
        md.append("")

    with open(output_path, 'w') as f:
        f.write("\n".join(md))

    print(f"✓ Markdown report saved to: {output_path}")


def main():
    """Main CLI entry point."""
    print("Blue Team Codebase Security Scanner")
    print("=" * 80)

    # Define base paths to scan
    base_paths = [
        "/var/www/html/wordpress/wp-content/plugins",
        "/var/www/html/wordpress/wp-content/mu-plugins",
        "/opt/claude-workspace/projects"
    ]

    print("\nScanning projects in:")
    for path in base_paths:
        print(f"  - {path}")

    scanner = get_scanner()
    results = scanner.scan_all_projects(base_paths)

    if not results:
        print("\n✅ No security issues found in any projects!")
        return 0

    # Print console summary
    print_summary(results)
    print_issues_by_category(results)
    print_top_projects(results)

    # Generate reports
    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"codebase-security-scan-{timestamp}.json"
    md_path = reports_dir / f"codebase-security-scan-{timestamp}.md"

    generate_json_report(results, json_path)
    generate_markdown_report(results, md_path)

    print("\n" + "=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)

    # Return exit code based on critical issues
    critical_count = sum(r.critical_count for r in results)
    if critical_count > 0:
        print(f"\n⚠️  WARNING: {critical_count} CRITICAL issues require immediate attention!")
        return 1
    else:
        print("\n✅ No critical issues found")
        return 0


if __name__ == "__main__":
    sys.exit(main())
