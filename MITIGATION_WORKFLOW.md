# Security Mitigation Workflow

**Status:** ✅ ACTIVE
**Last Updated:** 2026-03-07

---

## Overview

This document describes the **complete lifecycle** of security vulnerabilities from detection to resolution, including how the system tracks "negative findings" (fixed issues).

---

## Vulnerability Lifecycle

```
┌─────────────┐
│   Scanner   │ ← Runs hourly
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Issue Tracker   │ ← Detects changes
│ - NEW issues    │
│ - FIXED issues  │
│ - PERSISTENT    │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Dashboard +     │ ← Auto-generated daily
│ TODO Files      │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Developer      │ ← Reviews and fixes
│  Action         │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Next Scan      │ ← Detects fix = "FIXED" log entry
└─────────────────┘
```

---

## Tracking Negative Findings (Fixed Issues)

### How It Works

**Issue Tracker** (`blueteam/api/issue_tracker.py`) uses **issue signatures** to identify specific vulnerabilities across scans:

**Signature Components:**
- File path
- Line number
- Category (sql_injection, xss, etc.)
- Code snippet hash (24-bit)

**Example Signature:**
```
/var/www/html/wordpress/wp-content/plugins/cxq-facebot/show_main_page.php:172:xss:a3f2c1
```

### Detection Process

**On each scan:**

1. **Extract current issues** from scan report
2. **Load previous issues** from state file
3. **Calculate differences:**
   - `NEW = current - previous` (new vulnerabilities)
   - `FIXED = previous - current` (resolved vulnerabilities)
   - `PERSISTENT = current ∩ previous` (still present)

4. **Log changes** to changelog (`.scan-state/issue_changelog.jsonl`)

5. **Update metrics** (`.scan-state/mitigation_metrics.json`)

### State Files

**Location:** `/opt/claude-workspace/projects/cyber-guardian/.scan-state/`

**Files:**
- `current_issues.json` - Active vulnerabilities from latest scan
- `issue_changelog.jsonl` - Complete history of all changes (JSONL format)
- `mitigation_metrics.json` - Cumulative statistics and trends

---

## Example: Fixing an Issue

### Step 1: Identify Issue in TODO

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/TODO_SECURITY.md`

```markdown
## HIGH Priority

### Cross Site Scripting (2 issues)

**1. show_main_page.php:172**

```php
value="<?php echo $_GET['q']??$params['q']; ?>"
```

**Issue:** User input echoed without sanitization

**Fix:** Use esc_attr() to sanitize output

- [ ] Reviewed
- [ ] Fixed
- [ ] Tested
```

### Step 2: Implement Fix

```php
// BEFORE (vulnerable):
value="<?php echo $_GET['q']??$params['q']; ?>"

// AFTER (secure):
value="<?php echo esc_attr($_GET['q'] ?? $params['q'] ?? ''); ?>"
```

### Step 3: Next Hourly Scan Detects Fix

**Scanner runs at top of hour:**
```
[2026-03-07 11:00:00] Starting hourly security scan...
[2026-03-07 11:00:45] Tracking individual vulnerabilities...
[2026-03-07 11:00:46] Scan complete: 4070 issues (3410 CRITICAL, 116 HIGH, 544 MEDIUM)
[2026-03-07 11:00:46] ✓ FIXED: 1 vulnerability resolved
[2026-03-07 11:00:46] Hourly scan complete
```

### Step 4: Changelog Updated

**File:** `.scan-state/issue_changelog.jsonl`

New entry appended:
```json
{
  "signature": "/var/www/.../cxq-facebot/show_main_page.php:172:xss:a3f2c1",
  "timestamp": "2026-03-07T11:00:46.123456",
  "change_type": "fixed"
}
```

### Step 5: Metrics Updated

**File:** `.scan-state/mitigation_metrics.json`

```json
{
  "current": {
    "last_updated": "2026-03-07T11:00:46.123456",
    "total_issues": 4070,
    "new_this_scan": 0,
    "fixed_this_scan": 1,
    "persistent_issues": 4069,
    "net_change": -1,
    "cumulative_fixed": 12,
    "cumulative_new": 11,
    "net_improvement": 1
  },
  "history": [
    ...
    {
      "timestamp": "2026-03-07T11:00:46.123456",
      "total": 4070,
      "new": 0,
      "fixed": 1,
      "net_change": -1
    }
  ]
}
```

---

## Viewing Progress

### Recent Fixes

**Last 24 hours:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 -c "
from blueteam.api.issue_tracker import IssueTracker
tracker = IssueTracker('.scan-state')
fixes = tracker.get_recent_fixes(hours=24)
print(f'Fixed in last 24h: {len(fixes)} issues')
for fix in fixes:
    print(f\"  {fix.get('signature', 'unknown')}\")
"
```

### Cumulative Metrics

**7-day summary:**
```bash
jq '.current' .scan-state/mitigation_metrics.json
```

Output:
```json
{
  "last_updated": "2026-03-07T11:00:46.123456",
  "total_issues": 4070,
  "new_this_scan": 0,
  "fixed_this_scan": 1,
  "cumulative_fixed": 12,
  "cumulative_new": 11,
  "net_improvement": 1
}
```

### Trend Analysis

**View fix trend over time:**
```bash
jq '.history[] | {time: .timestamp, fixed: .fixed, new: .new, net: .net_change}' \
  .scan-state/mitigation_metrics.json | tail -20
```

---

## Mitigation Dashboard

### Auto-Generated Daily

**Location:** `/opt/claude-workspace/projects/cyber-guardian/MITIGATION_DASHBOARD.md`

**Schedule:** Generated at midnight (00:00) by hourly scan script

**Contents:**
- Overall statistics (total issues by severity)
- Projects ranked by priority (CRITICAL → HIGH → total)
- Links to project-specific TODO files
- Quick action commands

**Example:**
```markdown
## Projects Requiring Attention

| Project | Critical | High | Medium | Total | TODO |
|---------|----------|------|--------|-------|------|
| cxq-membership | 241 | 7 | 12 | 260 | [TODO](.../TODO_SECURITY.md) |
| cxq-scheduler | 231 | 2 | 10 | 243 | [TODO](.../TODO_SECURITY.md) |
```

### Project-Specific TODO Files

**Location:** `{project_path}/TODO_SECURITY.md`

**Auto-generated for each project** with vulnerabilities.

**Contents:**
- Summary table (severity counts)
- Issues grouped by severity and category
- Each issue includes:
  - File path and line number
  - Code snippet
  - Description
  - Recommendation
  - CWE ID
  - Checkboxes: [ ] Reviewed, [ ] Fixed, [ ] Tested

**Filters:**
- Excludes likely false positives (e.g., PDF parser string concatenation)
- Groups similar issues together
- Prioritizes CRITICAL and HIGH

---

## Streamlined Mitigation Workflow

### Daily Routine (For Security Team)

**Every morning:**

1. **Check dashboard for changes:**
   ```bash
   cat MITIGATION_DASHBOARD.md | head -30
   ```

2. **Review scan log for overnight fixes:**
   ```bash
   grep "FIXED:" .scan-state/scan.log | tail -10
   ```

3. **Prioritize today's work:**
   - Focus on CRITICAL issues first
   - Target projects with highest issue counts
   - Review TODO files for specific tasks

### Developer Workflow

**When working on a plugin:**

1. **Check for security TODO:**
   ```bash
   cat /var/www/html/wordpress/wp-content/plugins/MY-PLUGIN/TODO_SECURITY.md
   ```

2. **Review issues marked for your plugin**

3. **Implement fixes** following recommendations

4. **Mark checkboxes** as you complete each step:
   - [x] Reviewed
   - [x] Fixed
   - [x] Tested

5. **Commit changes:**
   ```bash
   git commit -m "Fix XSS vulnerability in show_main_page.php

   - Added esc_attr() sanitization to user input
   - Resolves TODO_SECURITY.md item #1

   Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
   ```

6. **Wait for next hourly scan** - fix will be automatically detected

### Weekly Review (For Management)

**Every Monday:**

1. **Review cumulative metrics:**
   ```bash
   jq '.current' .scan-state/mitigation_metrics.json
   ```

2. **Check net improvement:**
   - Positive = more fixes than new issues (good!)
   - Negative = more new issues than fixes (needs attention)

3. **Identify stalled projects:**
   - Check dashboard for projects with persistent HIGH/CRITICAL
   - Assign resources to high-priority projects

---

## False Positive Management

### Current False Positive Filters

**SQL Injection - PDF Parser String Concatenation:**
```python
if (issue['category'] == 'sql_injection' and
    'pdf-parser' in issue['file'].lower() and
    'output .=' in issue['code_snippet']):
    return True  # Skip - not actual SQL
```

**SQL Injection - Non-Database String Concatenation:**
```python
if (issue['category'] == 'sql_injection' and
    'output .=' in issue['code_snippet'] and
    '$wpdb' not in issue['code_snippet']):
    return True  # Skip - no database involved
```

### Adding Custom Filters

**Edit:** `scripts/generate-mitigation-todos.py`

**Function:** `is_likely_false_positive(issue)`

**Example - Add filter for known vendor code:**
```python
def is_likely_false_positive(issue):
    # ... existing filters ...

    # Vendor library - known safe pattern
    if ('vendor/' in issue['file'] and
        issue['category'] == 'sql_injection'):
        return True

    return False
```

**Re-generate TODOs:**
```bash
python3 scripts/generate-mitigation-todos.py
```

---

## Metrics Glossary

| Metric | Definition |
|--------|------------|
| **new_this_scan** | Vulnerabilities that appeared since last scan |
| **fixed_this_scan** | Vulnerabilities that disappeared since last scan |
| **persistent_issues** | Vulnerabilities present in both scans |
| **net_change** | `new - fixed` (negative = improvement) |
| **cumulative_fixed** | Total fixes in last 7 days |
| **cumulative_new** | Total new issues in last 7 days |
| **net_improvement** | `cumulative_fixed - cumulative_new` |

**Goal:** Maintain positive net_improvement (more fixes than new issues)

---

## Automation Summary

### What Runs Automatically

**Hourly (at :00):**
- Full codebase security scan
- Issue signature tracking
- Change detection (new/fixed/persistent)
- Changelog updates
- Metrics updates
- Scan log entries

**Daily (at 00:00):**
- TODO file generation for all projects
- Mitigation dashboard update
- False positive filtering

**Weekly (automatic cleanup):**
- Remove scan reports older than 7 days
- Trim changelog history (keep last 168 hours)

### What Requires Manual Action

- **Reviewing** TODO files
- **Implementing** fixes
- **Testing** changes
- **Committing** fixes to git
- **Adding** false positive filters (if needed)
- **Deploying** fixes to production

---

## Benefits of This System

### For Developers

✅ **Clear actionable items** - Each TODO has specific file, line, and fix recommendation
✅ **Automatic progress tracking** - Fixes detected without manual updates
✅ **False positive filtering** - Focus on real issues
✅ **Grouped by priority** - Work on CRITICAL first

### For Security Team

✅ **Continuous monitoring** - Hourly scans catch new issues fast
✅ **Trend visibility** - See if security is improving or degrading
✅ **Effort tracking** - Metrics show fixes per day/week
✅ **Centralized dashboard** - Single view of all projects

### For Management

✅ **Quantifiable metrics** - Report on net improvement
✅ **Resource allocation** - Identify projects needing help
✅ **Compliance documentation** - Audit trail in changelog
✅ **Risk visibility** - CRITICAL issue counts at a glance

---

## Troubleshooting

### Issue marked as fixed but still appears in scan

**Cause:** Issue signature didn't change (line number or code snippet different)

**Solution:** Check exact file/line in latest scan report vs TODO file

### Dashboard not updating

**Cause:** TODO generation only runs at midnight

**Solution:** Run manually:
```bash
python3 scripts/generate-mitigation-todos.py
```

### Too many false positives in TODO

**Cause:** Scanner pattern too broad

**Solution:** Add filter to `is_likely_false_positive()` function

### Metrics show negative net_improvement

**Cause:** More new issues than fixes

**Action:**
1. Check if new code introduced vulnerabilities
2. Prioritize fixing HIGH/CRITICAL backlog
3. Review recent commits for security issues
4. Consider pausing new features until net_improvement positive

---

## References

- **Scanner Implementation:** `blueteam/api/codebase_scanner.py`
- **Issue Tracker:** `blueteam/api/issue_tracker.py`
- **TODO Generator:** `scripts/generate-mitigation-todos.py`
- **Hourly Scan Script:** `scripts/hourly-security-scan.sh`
- **Mitigation Plan:** `SECURITY_MITIGATION_PLAN.md`
- **Dashboard:** `MITIGATION_DASHBOARD.md`
- **Automated Scanning Docs:** `AUTOMATED_SCANNING.md`

---

**Last Review:** 2026-03-07
**Next Review:** 2026-03-14
**Status:** ✅ PRODUCTION - ACTIVE
