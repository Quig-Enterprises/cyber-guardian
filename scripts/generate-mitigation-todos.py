#!/usr/bin/env python3
"""
Generate Mitigation TODO Items

Creates actionable TODO items for security vulnerabilities:
- Groups by project and severity
- Prioritizes CRITICAL and HIGH issues
- Excludes likely false positives
- Generates plugin-specific TODO.md files
- Creates summary dashboard
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def load_latest_scan():
    """Find and load the latest scan report"""
    reports_dir = Path(__file__).parent.parent / "reports"
    json_files = sorted(reports_dir.glob("codebase-security-scan-*.json"), reverse=True)

    if not json_files:
        print("ERROR: No scan reports found")
        sys.exit(1)

    latest = json_files[0]
    with open(latest, 'r') as f:
        return json.load(f)


def is_likely_false_positive(issue):
    """Detect common false positives"""
    # SQL injection on PDF parser string concatenation
    if (issue['category'] == 'sql_injection' and
        'pdf-parser' in issue['file'].lower() and
        'output .=' in issue['code_snippet']):
        return True

    # String concatenation that's clearly not SQL
    if (issue['category'] == 'sql_injection' and
        'output .=' in issue['code_snippet'] and
        '$wpdb' not in issue['code_snippet']):
        return True

    return False


def group_issues_by_project(scan_report):
    """Group issues by project, excluding false positives"""
    projects = defaultdict(lambda: {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'path': None
    })

    for project in scan_report['projects']:
        project_name = project['name']
        projects[project_name]['path'] = project['path']

        for issue in project['issues']:
            # Skip likely false positives
            if is_likely_false_positive(issue):
                continue

            severity = issue['severity'].lower()
            if severity in projects[project_name]:
                projects[project_name][severity].append(issue)

    return projects


def generate_project_todo(project_name, issues, project_path):
    """Generate TODO.md content for a project"""
    todo_content = f"""# Security Vulnerabilities - {project_name}

**Auto-generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Source:** Blue Team Codebase Scanner
**Status:** Requires Review

---

## Summary

"""

    # Count by severity
    critical_count = len(issues['critical'])
    high_count = len(issues['high'])
    medium_count = len(issues['medium'])

    total = critical_count + high_count + medium_count

    if total == 0:
        return None  # No issues, don't create file

    todo_content += f"| Severity | Count |\n"
    todo_content += f"|----------|-------|\n"

    if critical_count > 0:
        todo_content += f"| **CRITICAL** | **{critical_count}** |\n"
    if high_count > 0:
        todo_content += f"| **HIGH** | **{high_count}** |\n"
    if medium_count > 0:
        todo_content += f"| MEDIUM | {medium_count} |\n"

    todo_content += f"\n**Total:** {total} issues\n\n"

    # Add issues by severity
    for severity in ['critical', 'high', 'medium']:
        severity_issues = issues[severity]
        if not severity_issues:
            continue

        todo_content += f"## {severity.upper()} Priority\n\n"

        # Group by category
        by_category = defaultdict(list)
        for issue in severity_issues:
            by_category[issue['category']].append(issue)

        for category, cat_issues in sorted(by_category.items()):
            category_name = category.replace('_', ' ').title()
            todo_content += f"### {category_name} ({len(cat_issues)} issues)\n\n"

            # List each issue
            for i, issue in enumerate(cat_issues, 1):
                file_relative = issue['file'].replace(project_path + '/', '')
                todo_content += f"**{i}. {file_relative}:{issue['line']}**\n\n"
                todo_content += f"```php\n{issue['code_snippet']}\n```\n\n"
                todo_content += f"**Issue:** {issue['description']}\n\n"
                todo_content += f"**Fix:** {issue['recommendation']}\n\n"

                if 'cwe_id' in issue:
                    todo_content += f"**CWE:** {issue['cwe_id']}\n\n"

                todo_content += "- [ ] Reviewed\n"
                todo_content += "- [ ] Fixed\n"
                todo_content += "- [ ] Tested\n\n"
                todo_content += "---\n\n"

    todo_content += f"""
## Next Steps

1. **Review** each issue to confirm it's a real vulnerability (not false positive)
2. **Prioritize** CRITICAL and HIGH severity issues
3. **Implement** fixes following the recommendations
4. **Test** changes to ensure functionality is preserved
5. **Commit** fixes with descriptive messages
6. **Re-scan** to verify issues are resolved

## Notes

- Some SQL injection warnings may be false positives (string concatenation without database queries)
- File upload issues may be mitigated by global malware scanning (check mu-plugins)
- XSS issues require proper escaping with `esc_attr()`, `esc_html()`, `esc_url()`, etc.

---

**See also:** `/opt/claude-workspace/projects/cyber-guardian/SECURITY_MITIGATION_PLAN.md`
"""

    return todo_content


def generate_dashboard(projects_summary):
    """Generate mitigation dashboard"""
    dashboard = f"""# Security Mitigation Dashboard

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Source:** Blue Team Codebase Scanner
**Auto-updated:** Hourly

---

## Overview

"""

    # Calculate totals
    total_projects_with_issues = len([p for p in projects_summary.values()
                                     if sum(len(p[s]) for s in ['critical', 'high', 'medium']) > 0])
    total_critical = sum(len(p['critical']) for p in projects_summary.values())
    total_high = sum(len(p['high']) for p in projects_summary.values())
    total_medium = sum(len(p['medium']) for p in projects_summary.values())
    total_issues = total_critical + total_high + total_medium

    dashboard += f"| Metric | Count |\n"
    dashboard += f"|--------|-------|\n"
    dashboard += f"| Projects with Issues | {total_projects_with_issues} |\n"
    dashboard += f"| **CRITICAL Issues** | **{total_critical}** |\n"
    dashboard += f"| **HIGH Issues** | **{total_high}** |\n"
    dashboard += f"| MEDIUM Issues | {total_medium} |\n"
    dashboard += f"| **Total Issues** | **{total_issues}** |\n\n"

    dashboard += "---\n\n"
    dashboard += "## Projects Requiring Attention\n\n"
    dashboard += "| Project | Critical | High | Medium | Total | TODO |\n"
    dashboard += "|---------|----------|------|--------|-------|------|\n"

    # Sort by priority (critical desc, high desc, total desc)
    sorted_projects = sorted(
        projects_summary.items(),
        key=lambda x: (
            len(x[1]['critical']),
            len(x[1]['high']),
            len(x[1]['critical']) + len(x[1]['high']) + len(x[1]['medium'])
        ),
        reverse=True
    )

    for project_name, issues in sorted_projects:
        critical = len(issues['critical'])
        high = len(issues['high'])
        medium = len(issues['medium'])
        total = critical + high + medium

        if total == 0:
            continue

        # Generate TODO link if file exists
        todo_path = Path(issues['path']) / "TODO_SECURITY.md"
        if todo_path.exists():
            todo_link = f"[TODO]({todo_path})"
        else:
            todo_link = "—"

        dashboard += f"| {project_name} | {critical} | {high} | {medium} | {total} | {todo_link} |\n"

    dashboard += "\n---\n\n"
    dashboard += "## Quick Actions\n\n"
    dashboard += "**View all security TODOs:**\n"
    dashboard += "```bash\n"
    dashboard += "find /var/www/html/eqmon /opt/claude-workspace/projects /opt/artemis/www -name 'TODO_SECURITY.md'\n"
    dashboard += "```\n\n"
    dashboard += "**Run new scan:**\n"
    dashboard += "```bash\n"
    dashboard += "cd /opt/claude-workspace/projects/cyber-guardian\n"
    dashboard += "python3 blueteam/cli_codebase_scan.py\n"
    dashboard += "```\n\n"
    dashboard += "**Generate fresh TODOs:**\n"
    dashboard += "```bash\n"
    dashboard += "python3 scripts/generate-mitigation-todos.py\n"
    dashboard += "```\n\n"

    return dashboard


def main():
    """Generate TODO files for all projects with security issues"""
    print("Loading latest scan report...")
    scan_report = load_latest_scan()

    print("Grouping issues by project...")
    projects = group_issues_by_project(scan_report)

    print(f"Found {len(projects)} projects with potential issues")

    # Generate TODO files
    generated_count = 0
    for project_name, issues in projects.items():
        project_path = issues['path']
        if not project_path or not os.path.exists(project_path):
            continue

        todo_content = generate_project_todo(project_name, issues, project_path)
        if not todo_content:
            continue  # No real issues after filtering

        todo_file = os.path.join(project_path, "TODO_SECURITY.md")

        # Write TODO file
        with open(todo_file, 'w') as f:
            f.write(todo_content)

        print(f"✓ Generated: {todo_file}")
        generated_count += 1

    # Generate dashboard
    dashboard_file = Path(__file__).parent.parent / "MITIGATION_DASHBOARD.md"
    dashboard_content = generate_dashboard(projects)

    with open(dashboard_file, 'w') as f:
        f.write(dashboard_content)

    print(f"✓ Generated: {dashboard_file}")

    print(f"\n{'='*60}")
    print(f"Generated {generated_count} TODO files")
    print(f"Dashboard: {dashboard_file}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
