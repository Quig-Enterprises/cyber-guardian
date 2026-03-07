# Quick Start: Security Mitigation

**For developers fixing security vulnerabilities**

---

## 1. Find Your TODO File

```bash
# Check if your plugin has security issues
ls /var/www/html/wordpress/wp-content/plugins/MY-PLUGIN/TODO_SECURITY.md
```

**If file exists:** You have security issues to review

**If file doesn't exist:** No issues found (good!)

---

## 2. Review Issues

```bash
cat /var/www/html/wordpress/wp-content/plugins/MY-PLUGIN/TODO_SECURITY.md
```

**Issues are organized by:**
- CRITICAL (fix immediately)
- HIGH (fix soon)
- MEDIUM (fix when possible)

**Each issue shows:**
- File and line number
- Code snippet with problem
- What's wrong
- How to fix it
- CWE security reference

---

## 3. Fix the Issue

**Follow the recommendation** in the TODO file.

**Common fixes:**

**XSS (Cross-Site Scripting):**
```php
// BEFORE:
echo $_GET['q'];

// AFTER:
echo esc_attr($_GET['q'] ?? '');
```

**SQL Injection:**
```php
// BEFORE:
$wpdb->query("SELECT * FROM table WHERE id = " . $id);

// AFTER:
$wpdb->prepare("SELECT * FROM table WHERE id = %d", $id);
```

**File Upload:**
Already protected by global ClamAV malware scanning (see mu-plugins).

---

## 4. Mark Your Progress

**As you work, check off items in TODO_SECURITY.md:**

```markdown
- [x] Reviewed   ← I understand the issue
- [x] Fixed      ← I implemented the fix
- [x] Tested     ← I verified it works
```

---

## 5. Commit Your Fix

```bash
git add show_main_page.php
git commit -m "Fix XSS vulnerability in search parameter

- Added esc_attr() sanitization to user input
- Resolves TODO_SECURITY.md item #1

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## 6. Wait for Automatic Verification

**The system automatically detects your fix:**

- Next hourly scan runs (at top of hour)
- Issue signature no longer appears
- Logged as "FIXED" in changelog
- Removed from next TODO generation

**Check the log:**
```bash
grep "FIXED" /opt/claude-workspace/projects/cyber-guardian/.scan-state/scan.log | tail -5
```

You'll see something like:
```
[2026-03-07 11:00:46] ✓ FIXED: 1 vulnerability resolved
```

---

## Common Questions

**Q: The TODO says "SQL injection" but it's not database code?**

A: Likely a false positive. String concatenation triggers the scanner. Mark as "Reviewed" and skip.

**Q: My plugin has 100+ issues - where do I start?**

A: Focus on CRITICAL first, then HIGH. Many may be false positives - review before fixing.

**Q: I fixed it but it still appears in the TODO?**

A: TODO regenerates daily at midnight. Check tomorrow or run manually:
```bash
python3 /opt/claude-workspace/projects/cyber-guardian/scripts/generate-mitigation-todos.py
```

**Q: How do I know if I'm making progress?**

A: Check the dashboard:
```bash
cat /opt/claude-workspace/projects/cyber-guardian/MITIGATION_DASHBOARD.md | head -20
```

Or view metrics:
```bash
jq '.current' /opt/claude-workspace/projects/cyber-guardian/.scan-state/mitigation_metrics.json
```

---

## Need Help?

**View detailed workflow:**
```bash
cat /opt/claude-workspace/projects/cyber-guardian/MITIGATION_WORKFLOW.md
```

**See mitigation plan:**
```bash
cat /opt/claude-workspace/projects/cyber-guardian/SECURITY_MITIGATION_PLAN.md
```

**Run manual scan:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 blueteam/cli_codebase_scan.py
```

---

**Dashboard:** `/opt/claude-workspace/projects/cyber-guardian/MITIGATION_DASHBOARD.md`
**Your TODO:** `/var/www/html/wordpress/wp-content/plugins/YOUR-PLUGIN/TODO_SECURITY.md`
