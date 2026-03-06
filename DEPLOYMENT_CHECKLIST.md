# Malware Dashboard - Deployment Checklist

**Version:** 1.0.0
**Date:** 2026-03-06
**Estimated Time:** 45 minutes
**Status:** Ready for Final Deployment

---

## Overview

This checklist completes the final 30% of the malware dashboard deployment. All code is written and deployed - we just need to configure the scan scripts and verify everything works end-to-end.

**Current Status:** 70% Complete (Database ✅, API ✅, UI ✅)
**Remaining:** 30% (Configuration & Testing)

---

## Pre-Deployment Verification

### ✅ Already Complete

Check these are done (should all be ✅):

- [x] Database schema deployed (`blueteam` schema in `eqmon` database)
- [x] API files deployed (`/var/www/html/alfred/dashboard/security-dashboard/api/malware.php`)
- [x] UI files deployed (`index.php`, `security.css`, `security.js`)
- [x] Log parser script exists (`/opt/claude-workspace/shared-resources/scripts/parse-malware-logs.py`)
- [x] Python dependencies installed (`psycopg2`)

**Verify:**
```bash
# Check database
PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon \
  -c "SELECT COUNT(*) FROM blueteam.malware_scans;"

# Check API file
ls -lh /var/www/html/alfred/dashboard/security-dashboard/api/malware.php

# Check parser
ls -lh /opt/claude-workspace/shared-resources/scripts/parse-malware-logs.py

# Check Python
python3 -c "import psycopg2; print('✓ psycopg2 installed')"
```

**Expected:** All commands succeed

---

## Deployment Steps

### Step 1: Fix API Timestamp Casting (5 minutes)

**Issue:** The `malware.php` API calls `get_scan_stats()` with wrong timestamp type.

**File:** `/var/www/html/alfred/dashboard/security-dashboard/api/malware.php`

**Line:** 71-74

**Current Code:**
```php
    $stmt = $pdo->query("
        SELECT * FROM blueteam.get_scan_stats(
            CURRENT_TIMESTAMP - INTERVAL '30 days',
            CURRENT_TIMESTAMP
        )
```

**Change To:**
```php
    $stmt = $pdo->query("
        SELECT * FROM blueteam.get_scan_stats(
            (CURRENT_TIMESTAMP - INTERVAL '30 days')::timestamp without time zone,
            CURRENT_TIMESTAMP::timestamp without time zone
        )
```

**How to Fix:**

```bash
# Option 1: Use nano
sudo nano /var/www/html/alfred/dashboard/security-dashboard/api/malware.php
# Navigate to line 71, make the change, save (Ctrl+O, Enter, Ctrl+X)

# Option 2: Use sed (automatic)
sudo sed -i '72s/CURRENT_TIMESTAMP - INTERVAL/(CURRENT_TIMESTAMP - INTERVAL/' \
  /var/www/html/alfred/dashboard/security-dashboard/api/malware.php
sudo sed -i '72s/days.*,/days'\'')\:\:timestamp without time zone,/' \
  /var/www/html/alfred/dashboard/security-dashboard/api/malware.php
sudo sed -i '73s/CURRENT_TIMESTAMP/CURRENT_TIMESTAMP\:\:timestamp without time zone/' \
  /var/www/html/alfred/dashboard/security-dashboard/api/malware.php
```

**Verify Fix:**
```bash
# Test API
php -r '
$_SERVER["HTTP_X_AUTH_USER_ID"] = "1";
ob_start();
include "/var/www/html/alfred/dashboard/security-dashboard/api/malware.php";
$output = ob_get_clean();
$data = json_decode($output, true);
if (isset($data["malware_score"])) {
    echo "✓ API working - Malware score: " . $data["malware_score"] . "\n";
} else {
    echo "✗ API error: " . $output . "\n";
}
'
```

**Expected Output:**
```
✓ API working - Malware score: 100
```

**Checklist:**
- [ ] File edited
- [ ] API test successful
- [ ] No errors in output

---

### Step 2: Deploy Scan Scripts (10 minutes)

**What This Does:**
- Creates 4 scan scripts: `clamav-daily-scan.sh`, `maldet-daily-scan.sh`, `rkhunter-weekly-scan.sh`, `chkrootkit-weekly-scan.sh`
- Configures cron jobs for automated scanning
- Integrates log parser with each scan
- Creates log directory

**Command:**
```bash
sudo bash /opt/claude-workspace/shared-resources/scripts/setup-malware-scans-v2.sh admin@quigs.com
```

**Interactive Prompts:**
- None - script runs automatically

**Expected Output:**
```
==========================================
Automated Malware Scanning Setup v2
==========================================

Alert email: admin@quigs.com

✓ Log parser found: /opt/claude-workspace/shared-resources/scripts/parse-malware-logs.py
[1/5] Creating ClamAV daily scan script...
[2/5] Creating maldet daily scan script...
[3/5] Creating rkhunter weekly scan script...
[4/5] Creating chkrootkit weekly scan script...
[5/5] Creating cron jobs...

==========================================
Setup Complete!
==========================================

Scan Schedule:
  Daily (2:00 AM)  - ClamAV scan of WordPress directories
  Daily (3:00 AM)  - Maldet scan of recent changes
  Weekly (Sunday)  - rkhunter rootkit scan
  Weekly (Sunday)  - chkrootkit system scan

Update Schedule:
  Every 6 hours    - ClamAV virus definitions
  Daily (1:00 AM)  - Maldet signatures
  Daily (1:30 AM)  - rkhunter database

Log Directory: /var/log/malware-scans
Alert Email: admin@quigs.com

✓ Database Integration: ENABLED
  Log parser: /opt/claude-workspace/shared-resources/scripts/parse-malware-logs.py
  Results will be automatically inserted into blueteam database
```

**Verify:**
```bash
# Check scan scripts created
ls -lh /usr/local/bin/*scan.sh

# Check cron jobs
cat /etc/cron.d/malware-scanning

# Check log directory
ls -ld /var/log/malware-scans
```

**Expected:**
- 4 scan scripts exist and are executable
- Cron file contains 7 jobs
- Log directory exists with 750 permissions

**Checklist:**
- [ ] Setup script completed without errors
- [ ] 4 scan scripts created
- [ ] Cron jobs configured
- [ ] Log directory exists
- [ ] "Database Integration: ENABLED" message shown

---

### Step 3: Run Initial Test Scan (15-30 minutes)

**Purpose:** Test the complete workflow: Scan → Log → Parse → Database → API → UI

**Command:**
```bash
sudo /usr/local/bin/clamav-daily-scan.sh
```

**What Happens:**
1. ClamAV scans `/var/www/html/` directory
2. Creates log file: `/var/log/malware-scans/clamav-YYYYMMDD.log`
3. Parser automatically runs after scan completes
4. Parser extracts data from log
5. Parser inserts data into database
6. Parser logs to syslog

**Duration:** 15-30 minutes (depends on number of files)

**Monitor Progress:**
```bash
# Watch scan log (in another terminal)
tail -f /var/log/malware-scans/clamav-$(date +%Y%m%d).log

# Watch parser logs
sudo journalctl -t clamav-parser -f
```

**After Scan Completes:**

**1. Verify log created:**
```bash
ls -lh /var/log/malware-scans/clamav-*.log
```

**Expected:** Log file exists with size > 0

**2. Check parser ran:**
```bash
sudo journalctl -t clamav-parser -n 20
```

**Expected Output:**
```
Mar 06 02:15:00 alfred parse-malware-logs[12345]: INFO - === Malware Log Parser Started ===
Mar 06 02:15:00 alfred parse-malware-logs[12345]: INFO - Parsing clamav log: /var/log/malware-scans/clamav-20260306.log
Mar 06 02:15:01 alfred parse-malware-logs[12345]: INFO - ClamAV scan parsed: clean, 156789 files, 0 infections
Mar 06 02:15:01 alfred parse-malware-logs[12345]: INFO - Inserted scan record: scan_id=5
```

**3. Verify database updated:**
```bash
PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon <<'EOF'
-- Check latest scan
SELECT scan_type, scan_date, status, files_scanned, infections_found
FROM blueteam.v_latest_scans
WHERE scan_type = 'clamav';

-- Check malware score
SELECT blueteam.calculate_malware_score() as score;
EOF
```

**Expected Output:**
```
 scan_type |      scan_date      | status | files_scanned | infections_found
-----------+---------------------+--------+---------------+------------------
 clamav    | 2026-03-06 02:15:00 | clean  |        156789 |                0

  score
--------
 100.00
```

**Checklist:**
- [ ] Scan completed without errors
- [ ] Log file created
- [ ] Parser ran (check journalctl)
- [ ] Database shows new scan record
- [ ] Malware score calculated correctly

---

### Step 4: Test API Endpoint (5 minutes)

**Purpose:** Verify API returns complete data with real scan results.

**Command:**
```bash
curl -s -H "X-Auth-User-ID: 1" \
  http://localhost/dashboard/security-dashboard/api/malware.php \
  | python3 -m json.tool | head -80
```

**Expected Output:**
```json
{
  "malware_score": 100.0,
  "latest_scans": [
    {
      "scan_type": "clamav",
      "scan_date": "2026-03-06 02:15:00",
      "status": "clean",
      "files_scanned": 156789,
      "infections_found": 0,
      "scan_duration_seconds": 1245,
      "summary": {
        "known_viruses": 8694820,
        "engine_version": "1.4.3"
      }
    }
  ],
  "active_detections": [],
  "severity_counts": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "scan_stats": [...],
  "scan_history": [...],
  "last_scan_days": {
    "clamav": 0.1
  },
  "recent_scans": [...],
  "timestamp": "2026-03-06T02:30:00+00:00"
}
```

**Key Fields to Check:**
- `malware_score`: Should be 100.0 (no threats)
- `latest_scans`: Should contain ClamAV scan from Step 3
- `active_detections`: Should be empty array `[]`
- `severity_counts`: Should all be 0

**Checklist:**
- [ ] API returns valid JSON
- [ ] `malware_score` field present
- [ ] `latest_scans` contains ClamAV data
- [ ] `scan_stats` populated
- [ ] No error messages

---

### Step 5: Test Posture API (5 minutes)

**Purpose:** Verify malware score integrated into overall posture.

**Command:**
```bash
curl -s -H "X-Auth-User-ID: 1" \
  http://localhost/dashboard/security-dashboard/api/posture.php \
  | python3 -c "import sys, json; data=json.load(sys.stdin); print('Malware Score:', data['current'].get('malware', 'MISSING'))"
```

**Expected Output:**
```
Malware Score: 100.0
```

**Full Posture Check:**
```bash
curl -s -H "X-Auth-User-ID: 1" \
  http://localhost/dashboard/security-dashboard/api/posture.php \
  | python3 -m json.tool | grep -A 8 '"current"'
```

**Expected:**
```json
"current": {
  "overall": 87.5,
  "compliance": 92.0,
  "redteam": 85.0,
  "incident": 95.0,
  "monitoring": 80.0,
  "malware": 100.0
}
```

**Checklist:**
- [ ] Posture API returns valid JSON
- [ ] `malware` field present in `current` object
- [ ] `malware` value is 100.0
- [ ] Overall score calculation includes malware

---

### Step 6: Test Dashboard UI (10 minutes)

**Purpose:** Verify UI displays data correctly in browser.

**URL:** https://alfred.quigs.com/dashboard/security-dashboard/

**Browser Checklist:**

#### Posture Tab
- [ ] Malware score card visible (5th card)
- [ ] Displays "Malware" label
- [ ] Shows "10%" weight
- [ ] Score value is 100 (or close)
- [ ] Score is color-coded (green for 100)
- [ ] Other score weights updated:
  - [ ] Compliance: 30%
  - [ ] Red Team: 25%
  - [ ] Incident: 20%
  - [ ] Monitoring: 15%

#### Malware Tab
- [ ] "Malware" tab visible in navigation
- [ ] Click malware tab - loads without errors
- [ ] **Summary Cards (4 cards):**
  - [ ] Malware Defense Score: Shows 100
  - [ ] Scans Today: Shows 1 or more
  - [ ] Active Threats: Shows 0 (green)
  - [ ] Files Scanned (24h): Shows number > 0
- [ ] **Scan Results Grid:**
  - [ ] ClamAV card displays
  - [ ] Shows "CLEAN" status (green)
  - [ ] Shows files scanned count
  - [ ] Shows 0 infections
  - [ ] Shows scan duration
  - [ ] Shows last scan time
- [ ] **Active Detections Table:**
  - [ ] Table header shows "0" badge (green)
  - [ ] Table shows "No active detections - All clear!" message
- [ ] **Scanner Status Grid:**
  - [ ] ClamAV card shows "Active" status (green border)
  - [ ] Shows "< 1 day ago" or similar
  - [ ] Other scanners show "Never run" (if not run yet)

#### Browser Console (F12)
- [ ] No JavaScript errors in console
- [ ] No network errors (check Network tab)
- [ ] API calls return 200 status

#### Responsive Design
- [ ] Desktop view (>1024px): All cards in grid
- [ ] Tablet view (768px): Cards reflow correctly
- [ ] Mobile view (480px): Single column layout

**Screenshots (Optional):**
Take screenshots of:
1. Posture tab with malware score card
2. Malware tab summary cards
3. Scan results grid
4. Detections table (empty state)
5. Scanner status grid

---

## Post-Deployment Verification

### Test Complete Workflow

**Purpose:** Verify end-to-end data flow.

```
Scanner → Log File → Parser → Database → API → UI
  ✓         ✓         ✓         ✓        ✓     ✓
```

**Check Each Step:**

1. **Scanner Output:**
   ```bash
   tail -50 /var/log/malware-scans/clamav-*.log | grep "Infected files"
   ```
   Expected: `Infected files: 0`

2. **Parser Logs:**
   ```bash
   sudo journalctl -t clamav-parser -n 5
   ```
   Expected: "Inserted scan record" message

3. **Database:**
   ```bash
   PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon \
     -c "SELECT COUNT(*) as total_scans FROM blueteam.malware_scans;"
   ```
   Expected: Count ≥ 5 (4 sample + 1 real)

4. **API:**
   ```bash
   curl -s -H "X-Auth-User-ID: 1" \
     http://localhost/dashboard/security-dashboard/api/malware.php \
     | python3 -c "import sys, json; print('Latest scans:', len(json.load(sys.stdin)['latest_scans']))"
   ```
   Expected: `Latest scans: 1` or more

5. **UI:**
   - Visit dashboard
   - Click Malware tab
   - Verify ClamAV scan displays

**Checklist:**
- [ ] All 5 steps verified
- [ ] Data flows from scanner to UI
- [ ] Timestamps consistent across components

---

## Optional: Test Malware Detection

**Purpose:** Verify system detects and reports malware.

**⚠️ WARNING:** Only run this on a test system. This creates a harmless test virus file.

### Create EICAR Test File

```bash
# EICAR is a harmless test virus recognized by all scanners
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
```

### Run Scan

```bash
# Scan just the test file
sudo clamscan /tmp/eicar.com

# Or run full scan (will find it)
sudo /usr/local/bin/clamav-daily-scan.sh
```

### Verify Detection

**1. Check scan log:**
```bash
grep -i eicar /var/log/malware-scans/clamav-*.log
```

**Expected:**
```
/tmp/eicar.com: Win.Test.EICAR_HDB-1 FOUND
```

**2. Check database:**
```bash
PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon <<'EOF'
SELECT file_path, malware_signature, severity
FROM blueteam.v_active_detections
WHERE file_path LIKE '%eicar%';
EOF
```

**Expected:**
```
 file_path      | malware_signature      | severity
----------------+------------------------+----------
 /tmp/eicar.com | Win.Test.EICAR_HDB-1  | low
```

**3. Check malware score:**
```bash
PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon \
  -c "SELECT blueteam.calculate_malware_score();"
```

**Expected:** `95.00` (100 - 5 for low severity)

**4. Check dashboard:**
- Visit Malware tab
- Active Threats card should show: **1** (red background)
- Detections table should show: 1 row with EICAR detection
- Malware score should show: **95**

### Clean Up Test File

```bash
# Remove test file
sudo rm /tmp/eicar.com

# Mark detection as resolved
PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon <<'EOF'
UPDATE blueteam.malware_detections
SET resolved_at = NOW(),
    resolved_by = 'admin',
    resolution_notes = 'Test file - EICAR harmless test virus'
WHERE file_path = '/tmp/eicar.com';
EOF

# Verify score back to 100
PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon \
  -c "SELECT blueteam.calculate_malware_score();"
```

**Expected:** `100.00`

**Checklist:**
- [ ] Test file detected
- [ ] Detection in database
- [ ] Score decreased to 95
- [ ] Dashboard shows detection
- [ ] File removed
- [ ] Detection marked resolved
- [ ] Score back to 100

---

## Troubleshooting

### Issue: API Returns Error

**Symptom:**
```json
{"error":"Database query failed","message":"..."}
```

**Check:**
1. Database connection:
   ```bash
   PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon -c "SELECT 1"
   ```

2. View definitions:
   ```bash
   PGPASSWORD='Mtd2l6LXNlcnAiF25vZGVyZ' psql -h localhost -U eqmon -d eqmon \
     -c "\dv blueteam.*"
   ```

3. Test API directly:
   ```bash
   php -r '$_SERVER["HTTP_X_AUTH_USER_ID"] = "1"; include "/var/www/html/alfred/dashboard/security-dashboard/api/malware.php";'
   ```

**Fix:** Check Apache error log: `sudo tail -50 /var/log/apache2/error.log`

### Issue: Parser Not Running

**Symptom:** Scans complete but database not updated.

**Check:**
1. Parser script executable:
   ```bash
   chmod +x /opt/claude-workspace/shared-resources/scripts/parse-malware-logs.py
   ```

2. Python dependencies:
   ```bash
   python3 -c "import psycopg2; print('OK')"
   ```

3. Parser logs:
   ```bash
   sudo journalctl -t clamav-parser -n 50
   ```

**Fix:** Run parser manually to see errors:
```bash
python3 /opt/claude-workspace/shared-resources/scripts/parse-malware-logs.py --verbose
```

### Issue: Dashboard Not Loading

**Symptom:** Malware tab blank or shows errors.

**Check:**
1. Browser console (F12) for JavaScript errors
2. Network tab for failed API calls
3. Clear browser cache (Ctrl+Shift+R)

**Fix:**
- Verify files deployed: `ls -lh /var/www/html/alfred/dashboard/security-dashboard/`
- Check Apache error log: `sudo tail -50 /var/log/apache2/error.log`

### Issue: Cron Jobs Not Running

**Symptom:** No automated scans happening.

**Check:**
```bash
# Verify cron jobs exist
cat /etc/cron.d/malware-scanning

# Check cron service
sudo systemctl status cron

# Check cron logs
sudo journalctl -u cron --since today | grep malware
```

**Fix:**
```bash
# Restart cron service
sudo systemctl restart cron

# Manually test scan script
sudo /usr/local/bin/clamav-daily-scan.sh
```

---

## Final Verification Checklist

### System Components

- [ ] **Database:**
  - [ ] `blueteam` schema exists
  - [ ] 2 tables created and populated
  - [ ] 3 views working
  - [ ] 2 functions return correct values

- [ ] **Log Parser:**
  - [ ] Script exists and is executable
  - [ ] Python dependencies installed
  - [ ] Database connection works
  - [ ] Parser logs to syslog

- [ ] **API Endpoints:**
  - [ ] `/api/malware.php` returns valid JSON
  - [ ] `/api/posture.php` includes malware score
  - [ ] No authentication errors
  - [ ] Response times < 200ms

- [ ] **Dashboard UI:**
  - [ ] Malware tab visible
  - [ ] All 4 summary cards render
  - [ ] Scan results grid displays
  - [ ] Detections table works
  - [ ] Scanner status grid shows
  - [ ] No JavaScript errors
  - [ ] Mobile responsive

- [ ] **Scan Scripts:**
  - [ ] 4 scripts created
  - [ ] Scripts are executable
  - [ ] Cron jobs configured
  - [ ] Log directory exists
  - [ ] Parser integration enabled

### Functionality

- [ ] **Scanning:**
  - [ ] ClamAV scan completes
  - [ ] Log file created
  - [ ] Parser extracts data
  - [ ] Database updated

- [ ] **API:**
  - [ ] Malware score calculated
  - [ ] Latest scans returned
  - [ ] Active detections listed
  - [ ] Statistics computed

- [ ] **UI:**
  - [ ] Data displays correctly
  - [ ] Charts render (if implemented)
  - [ ] Tables sortable
  - [ ] Empty states show

- [ ] **Integration:**
  - [ ] Scan → Log → Parse → DB → API → UI
  - [ ] Posture score includes malware
  - [ ] Real-time updates work
  - [ ] Email alerts configured (optional)

---

## Success Criteria

**Deployment is complete when:**

✅ All 6 deployment steps completed
✅ No errors in logs (parser, API, Apache)
✅ Database contains real scan data
✅ API returns complete JSON
✅ Dashboard displays scan results
✅ Posture score includes malware (10%)
✅ At least one successful end-to-end workflow

---

## Deployment Complete! 🎉

**Congratulations!** The Malware Dashboard is now fully operational.

### What You Now Have

- ✅ Real-time malware defense scoring (0-100)
- ✅ 4 security scanners running automatically
- ✅ Automated log parsing and database updates
- ✅ RESTful API with comprehensive data
- ✅ Professional dashboard UI
- ✅ 30-day historical tracking
- ✅ Email alerts on detection
- ✅ Mobile-responsive design

### Next Steps

**Monitoring:**
- Check dashboard daily: https://alfred.quigs.com/dashboard/security-dashboard/
- Review weekly scan reports
- Monitor email alerts

**Maintenance:**
- Scanner signatures update automatically
- Logs rotate automatically (30-day retention)
- Database grows ~1MB per year (estimated)

**Optional Enhancements:**
- Add more scanners (Lynis, custom scripts)
- Create weekly email summaries
- Add detection resolution workflow
- Implement historical charts
- Configure Slack/Teams notifications

---

**Deployment Date:** _______________
**Deployed By:** _______________
**Status:** ☐ In Progress  ☐ Complete  ☐ Issues Found

**Notes:**
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

---

**Version:** 1.0.0
**Last Updated:** 2026-03-06
