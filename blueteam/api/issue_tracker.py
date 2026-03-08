#!/usr/bin/env python3
"""
Issue Tracker - Tracks security vulnerability lifecycle

Monitors vulnerabilities across scans to identify:
- New issues that appeared
- Fixed issues that disappeared
- Persistent issues still present
- Mitigation progress metrics
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, asdict


@dataclass
class IssueSignature:
    """Unique identifier for a security issue"""
    file: str
    line: int
    category: str
    severity: str
    code_snippet: str

    def to_key(self) -> str:
        """Generate unique key for this issue"""
        # Use file:line:category as primary key
        # Code snippet helps differentiate multiple issues on same line
        snippet_hash = hash(self.code_snippet.strip()) & 0xFFFFFF  # 24-bit hash
        return f"{self.file}:{self.line}:{self.category}:{snippet_hash:06x}"


@dataclass
class IssueChange:
    """Represents a change in issue status"""
    issue: IssueSignature
    timestamp: str
    change_type: str  # "new", "fixed", "persistent"

    def to_dict(self):
        return {
            **asdict(self.issue),
            'timestamp': self.timestamp,
            'change_type': self.change_type
        }


class IssueTracker:
    """Track security issues across multiple scans"""

    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        self.current_issues_file = os.path.join(state_dir, "current_issues.json")
        self.changelog_file = os.path.join(state_dir, "issue_changelog.jsonl")
        self.metrics_file = os.path.join(state_dir, "mitigation_metrics.json")

        os.makedirs(state_dir, exist_ok=True)

    def extract_issues(self, scan_report: dict) -> Set[str]:
        """Extract issue signatures from scan report"""
        issues = set()

        for project in scan_report.get('projects', []):
            for issue in project.get('issues', []):
                sig = IssueSignature(
                    file=issue['file'],
                    line=issue['line'],
                    category=issue['category'],
                    severity=issue['severity'],
                    code_snippet=issue.get('code_snippet', '')
                )
                issues.add(sig.to_key())

        return issues

    def extract_issues_with_details(self, scan_report: dict) -> Dict[str, dict]:
        """Extract issues with full details for reporting"""
        issues = {}

        for project in scan_report.get('projects', []):
            project_name = project['name']
            for issue in project.get('issues', []):
                sig = IssueSignature(
                    file=issue['file'],
                    line=issue['line'],
                    category=issue['category'],
                    severity=issue['severity'],
                    code_snippet=issue.get('code_snippet', '')
                )
                key = sig.to_key()
                issues[key] = {
                    **issue,
                    'project': project_name,
                    'signature': key
                }

        return issues

    def load_previous_issues(self) -> Set[str]:
        """Load issue signatures from previous scan"""
        if not os.path.exists(self.current_issues_file):
            return set()

        try:
            with open(self.current_issues_file, 'r') as f:
                data = json.load(f)
                return set(data.get('issues', []))
        except (json.JSONDecodeError, IOError):
            return set()

    def save_current_issues(self, issues: Set[str], timestamp: str):
        """Save current issue signatures"""
        with open(self.current_issues_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'count': len(issues),
                'issues': list(issues)
            }, f, indent=2)

    def log_change(self, change: IssueChange):
        """Append change to changelog (JSONL format)"""
        with open(self.changelog_file, 'a') as f:
            f.write(json.dumps(change.to_dict()) + '\n')

    def compare_scans(self, current_report: dict) -> Tuple[List[dict], List[str], List[str]]:
        """
        Compare current scan with previous scan

        Returns:
            (new_issues, fixed_issues, persistent_issues)
        """
        timestamp = current_report.get('generated', datetime.now().isoformat())

        # Extract current issues
        current_issues = self.extract_issues(current_report)
        current_details = self.extract_issues_with_details(current_report)

        # Load previous issues
        previous_issues = self.load_previous_issues()

        # Calculate differences
        new_issue_keys = current_issues - previous_issues
        fixed_issue_keys = previous_issues - current_issues
        persistent_issue_keys = current_issues & previous_issues

        # Build detailed new issues list
        new_issues = [
            current_details[key] for key in new_issue_keys
            if key in current_details
        ]

        # Log changes
        for key in new_issue_keys:
            if key in current_details:
                issue = current_details[key]
                sig = IssueSignature(
                    file=issue['file'],
                    line=issue['line'],
                    category=issue['category'],
                    severity=issue['severity'],
                    code_snippet=issue.get('code_snippet', '')
                )
                change = IssueChange(
                    issue=sig,
                    timestamp=timestamp,
                    change_type='new'
                )
                self.log_change(change)

        for key in fixed_issue_keys:
            # We don't have full details for fixed issues anymore
            # Just log the signature key
            change_dict = {
                'signature': key,
                'timestamp': timestamp,
                'change_type': 'fixed'
            }
            with open(self.changelog_file, 'a') as f:
                f.write(json.dumps(change_dict) + '\n')

        # Save current state for next comparison
        self.save_current_issues(current_issues, timestamp)

        # Update metrics
        self.update_metrics(
            new_count=len(new_issue_keys),
            fixed_count=len(fixed_issue_keys),
            persistent_count=len(persistent_issue_keys),
            timestamp=timestamp
        )

        return (
            new_issues,
            list(fixed_issue_keys),
            list(persistent_issue_keys)
        )

    def update_metrics(self, new_count: int, fixed_count: int,
                      persistent_count: int, timestamp: str):
        """Update mitigation progress metrics"""
        metrics = {
            'last_updated': timestamp,
            'total_issues': new_count + persistent_count,
            'new_this_scan': new_count,
            'fixed_this_scan': fixed_count,
            'persistent_issues': persistent_count,
            'net_change': new_count - fixed_count
        }

        # Load historical metrics
        history = []
        if os.path.exists(self.metrics_file):
            try:
                with open(self.metrics_file, 'r') as f:
                    data = json.load(f)
                    history = data.get('history', [])
            except (json.JSONDecodeError, IOError):
                pass

        # Append current scan to history
        history.append({
            'timestamp': timestamp,
            'total': metrics['total_issues'],
            'new': new_count,
            'fixed': fixed_count,
            'net_change': metrics['net_change']
        })

        # Keep last 168 hours (7 days of hourly scans)
        history = history[-168:]

        # Calculate cumulative stats
        total_fixed = sum(h['fixed'] for h in history)
        total_new = sum(h['new'] for h in history)

        metrics['cumulative_fixed'] = total_fixed
        metrics['cumulative_new'] = total_new

        # Net improvement: current total vs worst scan in the history window
        worst_total = max((h['total'] for h in history), default=metrics['total_issues'])
        metrics['net_improvement'] = worst_total - metrics['total_issues']
        metrics['baseline'] = worst_total

        # Save metrics
        with open(self.metrics_file, 'w') as f:
            json.dump({
                'current': metrics,
                'history': history
            }, f, indent=2)

    def get_recent_fixes(self, hours: int = 24) -> List[dict]:
        """Get issues fixed in the last N hours"""
        if not os.path.exists(self.changelog_file):
            return []

        cutoff = datetime.now().timestamp() - (hours * 3600)
        fixes = []

        with open(self.changelog_file, 'r') as f:
            for line in f:
                try:
                    change = json.loads(line.strip())
                    if change.get('change_type') == 'fixed':
                        # Parse timestamp
                        ts_str = change.get('timestamp', '')
                        try:
                            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                            if ts.timestamp() >= cutoff:
                                fixes.append(change)
                        except ValueError:
                            continue
                except json.JSONDecodeError:
                    continue

        return fixes

    def get_metrics_summary(self) -> dict:
        """Get current mitigation metrics"""
        if not os.path.exists(self.metrics_file):
            return {}

        try:
            with open(self.metrics_file, 'r') as f:
                data = json.load(f)
                return data.get('current', {})
        except (json.JSONDecodeError, IOError):
            return {}


def main():
    """Test the issue tracker"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: issue_tracker.py <scan_report.json>")
        sys.exit(1)

    report_file = sys.argv[1]
    state_dir = ".scan-state"

    with open(report_file, 'r') as f:
        report = json.load(f)

    tracker = IssueTracker(state_dir)
    new, fixed, persistent = tracker.compare_scans(report)

    print(f"New issues: {len(new)}")
    print(f"Fixed issues: {len(fixed)}")
    print(f"Persistent issues: {len(persistent)}")

    metrics = tracker.get_metrics_summary()
    print(f"\nMetrics:")
    print(f"  Net improvement (7 days): {metrics.get('net_improvement', 0)}")
    print(f"  Cumulative fixed: {metrics.get('cumulative_fixed', 0)}")
    print(f"  Cumulative new: {metrics.get('cumulative_new', 0)}")


if __name__ == '__main__':
    main()
