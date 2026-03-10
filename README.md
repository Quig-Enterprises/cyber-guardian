# Cyber-Guardian Security Platform

**Version:** 1.3.0
**Date:** 2026-03-10
**Status:** Production Ready
**License:** Proprietary - Quig Enterprises

---

## Overview

Comprehensive security monitoring, malware scanning, and infrastructure assessment platform. Provides real-time threat detection, CVE vulnerability scanning, and automated security assessments across infrastructure.

### Components

1. **Malware Dashboard Integration** - Real-time malware defense scoring with 4 security scanners
2. **CVE Assessment System** - Container vulnerability scanning with Trivy
3. **Infrastructure Security Audits** - AWS-compliant security assessments
4. **Compliance Scanner** - Multi-server infrastructure compliance monitoring with AWS checks
5. **Lynis CIS Auditing** - Comprehensive system hardening and CIS benchmark compliance

### Features

- 🛡️ **Real-time Malware Defense Score** (0-100)
- 🔍 **4 Security Scanners** (ClamAV, Maldet, RKHunter, Chkrootkit)
- 📊 **Historical Trend Analysis** (30-day window)
- 🚨 **Active Threat Detection** with severity classification
- 📱 **Responsive Dashboard UI** (mobile/tablet/desktop)
- ⚡ **Automated Log Parsing** and database integration
- 📧 **Email Alerts** on malware detection
- ✅ **Multi-Server Compliance Monitoring** (local, remote-SSH, AWS EC2)
- 🔐 **AWS Security Checks** (IMDSv2, EBS encryption, security groups)
- 📦 **MailCow Container Monitoring** (version, SSL, backups, health)
- 📈 **Compliance Scoring** (0-100) with CIS/NIST CSF mapping
- 🔒 **Lynis CIS Auditing** (200+ security tests, hardening index 0-100)
- 📊 **Combined Security Posture** (compliance + Lynis integrated view)

### Architecture

```
┌─────────────┐
│  Scanners   │ → Logs → Parser → PostgreSQL
│  (4 types)  │                      ↓
└─────────────┘              blueteam schema
                                     ↓
                              Views & Functions
                                     ↓
┌─────────────┐              RESTful API
│  Dashboard  │ ←────────────────────┘
│     UI      │
└─────────────┘
```

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Project Structure](#project-structure)
3. [Installation](#installation)
4. [Database Schema](#database-schema)
5. [Compliance Scanner](#compliance-scanner)
6. [Log Parser](#log-parser)
7. [API Endpoints](#api-endpoints)
8. [Dashboard UI](#dashboard-ui)
9. [Configuration](#configuration)
10. [Testing](#testing)
11. [Troubleshooting](#troubleshooting)
12. [Development](#development)
13. [License](#license)

---

## Quick Start

### Prerequisites

- PostgreSQL 12+
- Python 3.8+
- PHP 7.4+
- Apache/Nginx web server
- Malware scanners: ClamAV, Maldet, RKHunter, Chkrootkit

### Installation (5 Minutes)

```bash
# 1. Deploy database schema
cd /opt/claude-workspace/projects/cyber-guardian/sql
DB_NAME=eqmon DB_USER=eqmon bash deploy-phase1.sh

# 2. Install Python dependencies
pip install psycopg2-binary

# 3. Deploy scan scripts and cron jobs
sudo bash /opt/claude-workspace/shared-resources/scripts/setup-malware-scans-v2.sh admin@quigs.com

# 4. Run initial test scan
sudo /usr/local/bin/clamav-daily-scan.sh

# 5. Verify dashboard
# Visit: https://alfred.quigs.com/dashboard/security-dashboard/
# Click: Malware tab
```

**That's it!** The dashboard is now monitoring malware scans.

---

## Project Structure

```
cyber-guardian/
├── sql/                          # Database Schema
│   ├── 01-malware-schema.sql     # Malware tables, views, functions (525 lines)
│   ├── 01-malware-schema-rollback.sql
│   ├── 02-compliance-schema.sql  # Compliance tables, views, functions (703 lines)
│   ├── 02-compliance-schema-rollback.sql
│   ├── deploy-phase1.sh          # Automated malware schema deployment
│   ├── deploy-compliance-schema.sh # Automated compliance schema deployment
│   └── README.md                 # Database documentation
│
├── scripts/                      # Scanners & Parsers
│   ├── parse-malware-logs.py    # Malware log parser (645 lines)
│   ├── compliance-scanner.py    # Infrastructure compliance scanner (976 lines)
│   ├── setup-malware-scans-v2.sh # Malware scan setup (305 lines)
│   └── PHASE2_README.md          # Parser documentation
│
├── dashboard/api/                # API Endpoints
│   ├── malware.php               # Malware data API (152 lines)
│   ├── compliance-scans.php      # Compliance data API (514 lines)
│   ├── posture.php               # Security posture API
│   ├── COMPLIANCE_SCANS_API.md   # Compliance API documentation
│   ├── COMPLIANCE_SCANS_SUMMARY.md
│   └── COMPLIANCE_SCANS_VERIFICATION.md
│
├── dashboard/                    # UI Components
│   └── PHASE4_README.md          # UI documentation
│
├── findings/                     # Security Assessment Reports
│   ├── willie/                   # MailCow server assessments
│   └── COMPLIANCE_TEST_REPORT_2026-03-10.md
│
├── MALWARE_DASHBOARD_INTEGRATION_PLAN.md
└── README.md                     # This file
```

**Total Code:** ~2,500 lines
**Documentation:** ~3,645 lines

---

## Installation

### 1. Database Schema Deployment

**Location:** `sql/01-malware-schema.sql`

**Creates:**
- Tables: `malware_scans`, `malware_detections`
- Views: `v_latest_scans`, `v_active_detections`, `v_detection_summary`
- Functions: `calculate_malware_score()`, `get_scan_stats()`

**Deploy:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian/sql

# Set database credentials
export DB_NAME=eqmon
export DB_USER=eqmon

# Deploy schema
bash deploy-phase1.sh

# Verify deployment
psql -U eqmon -d eqmon -c "SELECT * FROM blueteam.v_latest_scans;"
```

**Expected Output:**
```
Tables created: 2/2
Views created: 3/3
Functions created: 2/2
Sample records: 4
Malware score: 100/100
```

**Rollback (if needed):**
```bash
bash deploy-phase1.sh --rollback
```

### 2. Python Dependencies

```bash
# Install psycopg2 for PostgreSQL connectivity
pip install psycopg2-binary

# Or use system package manager
sudo apt install python3-psycopg2

# Verify installation
python3 -c "import psycopg2; print('psycopg2 installed successfully')"
```

### 3. Log Parser & Scan Scripts

**Setup Script:** `scripts/setup-malware-scans-v2.sh`

**Creates:**
- `/usr/local/bin/clamav-daily-scan.sh` - Daily ClamAV scan
- `/usr/local/bin/maldet-daily-scan.sh` - Daily Maldet scan
- `/usr/local/bin/rkhunter-weekly-scan.sh` - Weekly RKHunter scan
- `/usr/local/bin/chkrootkit-weekly-scan.sh` - Weekly Chkrootkit scan
- `/etc/cron.d/malware-scanning` - Cron jobs

**Deploy:**
```bash
sudo bash /opt/claude-workspace/shared-resources/scripts/setup-malware-scans-v2.sh admin@quigs.com
```

**Scan Schedule:**
- **ClamAV:** Daily at 2:00 AM
- **Maldet:** Daily at 3:00 AM
- **RKHunter:** Weekly (Sunday) at 4:00 AM
- **Chkrootkit:** Weekly (Sunday) at 4:30 AM

**Signature Updates:**
- **ClamAV:** Every 6 hours
- **Maldet:** Daily at 1:00 AM
- **RKHunter:** Daily at 1:30 AM

### 4. API Endpoint Configuration

**Files:**
- `/var/www/html/alfred/dashboard/security-dashboard/api/malware.php`
- `/var/www/html/alfred/dashboard/security-dashboard/api/posture.php`

**Database Connection:**

File: `api/lib/db.php`
```php
$pdo = new PDO(
    'pgsql:host=localhost;dbname=eqmon',
    'eqmon',
    getenv('EQMON_AUTH_DB_PASS') ?: 'password_here'
);
```

**Update password** from `~/.pgpass`:
```bash
grep "^localhost:5432:eqmon:eqmon:" ~/.pgpass | cut -d: -f5
```

### 5. Dashboard UI Files

**Files already deployed:**
- `index.php` - Malware tab added
- `css/security.css` - Malware styles added
- `js/security.js` - Malware JavaScript added

**Cache Busting:**
```php
<link rel="stylesheet" href="css/security.css?v=20260306d">
<script src="js/security.js?v=20260306f"></script>
```

**Increment version** after CSS/JS changes.

---

## Database Schema

### Tables

#### blueteam.malware_scans

Stores scan execution metadata.

| Column | Type | Description |
|--------|------|-------------|
| scan_id | SERIAL | Primary key |
| scan_type | VARCHAR(20) | clamav, maldet, rkhunter, chkrootkit |
| scan_date | TIMESTAMP | When scan completed |
| status | VARCHAR(20) | clean, infected, warning, error |
| files_scanned | INTEGER | Total files scanned |
| infections_found | INTEGER | Number of infections |
| scan_duration_seconds | INTEGER | Scan duration |
| log_file_path | TEXT | Path to log file |
| summary | JSONB | Flexible scan metadata |
| created_at | TIMESTAMP | Record creation time |

**Indexes:**
- `idx_malware_scans_date` (scan_date DESC)
- `idx_malware_scans_type` (scan_type)
- `idx_malware_scans_type_date` (scan_type, scan_date DESC)
- `idx_malware_scans_status` (status)

#### blueteam.malware_detections

Stores individual malware findings.

| Column | Type | Description |
|--------|------|-------------|
| detection_id | SERIAL | Primary key |
| scan_id | INTEGER | Foreign key to malware_scans |
| file_path | TEXT | Infected file path |
| malware_signature | TEXT | Malware name/signature |
| severity | VARCHAR(20) | critical, high, medium, low |
| action_taken | VARCHAR(50) | quarantined, deleted, reported |
| detected_at | TIMESTAMP | Detection timestamp |
| resolved_at | TIMESTAMP | Resolution timestamp (NULL if active) |
| resolved_by | VARCHAR(100) | Who resolved it |
| resolution_notes | TEXT | Resolution details |
| created_at | TIMESTAMP | Record creation time |

**Indexes:**
- `idx_malware_detections_scan` (scan_id)
- `idx_malware_detections_severity` (severity)
- `idx_malware_detections_unresolved` (WHERE resolved_at IS NULL)
- `idx_malware_detections_file` (file_path)

### Views

#### blueteam.v_latest_scans

Latest scan for each scanner type.

```sql
SELECT * FROM blueteam.v_latest_scans;
```

**Columns:** scan_type, scan_date, status, files_scanned, infections_found, scan_duration_seconds, log_file_path, summary

#### blueteam.v_active_detections

Unresolved detections with scanner info.

```sql
SELECT * FROM blueteam.v_active_detections;
```

**Columns:** detection_id, scan_type, file_path, malware_signature, severity, action_taken, detected_at

#### blueteam.v_detection_summary

Detection counts by severity.

```sql
SELECT * FROM blueteam.v_detection_summary;
```

**Columns:** severity, count, most_recent, oldest

### Functions

#### blueteam.calculate_malware_score()

Returns real-time malware defense score (0-100).

```sql
SELECT blueteam.calculate_malware_score();
```

**Formula:**
```
score = 100 - (critical × 30 + high × 20 + medium × 10 + low × 5)
score = GREATEST(0, LEAST(100, score))
```

**Returns:** NUMERIC (0.00 to 100.00)

#### blueteam.get_scan_stats(start_date, end_date)

Historical scan statistics.

```sql
SELECT * FROM blueteam.get_scan_stats(
    NOW() - INTERVAL '30 days',
    NOW()
);
```

**Returns:** TABLE(scan_type, total_scans, total_files_scanned, total_infections, avg_duration_seconds, last_scan_date)

**Default:** Last 30 days if dates not provided

---

## Compliance Scanner

### Overview

**File:** `scripts/compliance-scanner.py` (976 lines)
**Version:** 1.1.0
**Status:** Production Ready

Multi-server infrastructure compliance monitoring with AWS-specific checks, MailCow container monitoring, and automated security assessment.

### Features

- **Multi-Server Support**: Local, remote-SSH, and AWS EC2 execution modes
- **Check Categories**: OS, SSH, Firewall, Docker, AWS, MailCow
- **AWS Auto-Detection**: Automatic EC2 instance metadata retrieval via IMDSv2
- **MailCow Monitoring**: Container versions, SSL certificates, backups, health checks
- **Compliance Scoring**: 0-100 score based on severity-weighted findings
- **Framework Mapping**: CIS Benchmarks, AWS Foundational Security, NIST CSF
- **Database Integration**: PostgreSQL blueteam schema with views and functions

### Quick Start

```bash
# 1. Deploy compliance schema
cd /opt/claude-workspace/projects/cyber-guardian/sql
DB_NAME=eqmon DB_USER=eqmon bash deploy-compliance-schema.sh

# 2. Scan local server
python3 scripts/compliance-scanner.py --server alfred --type local

# 3. Scan remote server via SSH
python3 scripts/compliance-scanner.py \
  --server peter \
  --type remote-ssh \
  --ssh-key ~/.ssh/bq_laptop_rsa

# 4. Scan AWS EC2 instance (auto-detects instance ID)
python3 scripts/compliance-scanner.py \
  --server willie \
  --type aws-ec2 \
  --ssh-key ~/.ssh/bq_laptop_rsa

# 5. View results
psql -U eqmon -d eqmon -c "SELECT * FROM blueteam.v_latest_compliance_scans;"
```

### Database Schema

**Tables:**
- `blueteam.compliance_scans` - Scan execution metadata
- `blueteam.compliance_findings` - Individual compliance findings

**Views:**
- `v_latest_compliance_scans` - Most recent scan per server
- `v_active_compliance_findings` - Unresolved findings
- `v_compliance_summary_by_server` - Aggregated stats per server
- `v_compliance_by_category` - Stats grouped by check category

**Functions:**
- `calculate_compliance_score(scan_id)` - Returns 0-100 score
- `get_compliance_stats(server_name, start_date, end_date)` - Historical stats

### Check Categories

#### OS Checks (Universal)

| Check ID | Name | Severity | Description |
|----------|------|----------|-------------|
| os-001 | Pending Security Updates | MEDIUM | Verifies no pending security updates |
| os-002 | Kernel Version Current | LOW | Checks kernel is reasonably current |
| os-003 | Unattended Upgrades Configured | MEDIUM | Validates automatic security updates |

**CIS Mapping:** CIS Ubuntu Linux 24.04 LTS Benchmark 1.1.1.2

#### SSH Checks (Universal)

| Check ID | Name | Severity | Description |
|----------|------|----------|-------------|
| ssh-001 | Root Login Disabled | LOW | PermitRootLogin no |
| ssh-002 | Password Authentication Disabled | LOW | PasswordAuthentication no |
| ssh-003 | Empty Passwords Prohibited | MEDIUM | PermitEmptyPasswords no |
| ssh-004 | SSH Protocol 2 Only | MEDIUM | Protocol 2 enforcement |

**CIS Mapping:** CIS Ubuntu Linux 24.04 LTS Benchmark 5.2.x

#### Firewall Checks (Universal)

| Check ID | Name | Severity | Description |
|----------|------|----------|-------------|
| fw-001 | Firewall Enabled | HIGH | UFW or iptables active |

**CIS Mapping:** CIS Ubuntu Linux 24.04 LTS Benchmark 3.5.1.1

#### Docker Checks (Universal)

| Check ID | Name | Severity | Description |
|----------|------|----------|-------------|
| docker-001 | Docker Version Current | MEDIUM | Docker >= 20.10.0 |
| docker-002 | No :latest Tags in Production | MEDIUM | Verifies version pinning |

**CIS Mapping:** CIS Docker Benchmark 1.0

#### AWS Checks (EC2 Only)

| Check ID | Name | Severity | Description |
|----------|------|----------|-------------|
| aws-001 | IMDSv2 Enforcement | HIGH | Metadata v2 required |
| aws-002 | EBS Encryption | HIGH | Root volume encrypted |

**Framework:** AWS Foundational Security Best Practices

#### MailCow Checks (MailCow Servers Only)

| Check ID | Name | Severity | Description |
|----------|------|----------|-------------|
| mailcow-001 | Container Versions | MEDIUM | MailCow version current (2026-01+) |
| mailcow-002 | SSL Certificate Expiration | HIGH/CRITICAL | Certificate > 30 days remaining |
| mailcow-003 | Docker Compose Running | CRITICAL | All containers healthy |
| mailcow-004 | Backup Verification | MEDIUM | Recent EBS snapshot exists |

**CIS Mapping:** CIS Docker Benchmark 1.0
**NIST CSF:** PR.IP-4 (Backups), PR.DS-2 (Data Security)

### Usage Examples

**Local Server Scan:**
```bash
python3 scripts/compliance-scanner.py \
  --server alfred \
  --type local
```

**Remote SSH Scan:**
```bash
python3 scripts/compliance-scanner.py \
  --server peter \
  --type remote-ssh \
  --ssh-key ~/.ssh/bq_laptop_rsa
```

**AWS EC2 Scan with Auto-Detection:**
```bash
# Auto-detects instance ID and region via IMDSv2
python3 scripts/compliance-scanner.py \
  --server willie \
  --type aws-ec2 \
  --ssh-key ~/.ssh/bq_laptop_rsa
```

**Manual AWS Instance ID:**
```bash
python3 scripts/compliance-scanner.py \
  --server willie \
  --type aws-ec2 \
  --ssh-key ~/.ssh/bq_laptop_rsa \
  --aws-instance-id i-0123456789abcdef0 \
  --aws-region us-east-2
```

**Verbose Output:**
```bash
python3 scripts/compliance-scanner.py \
  --server alfred \
  --type local \
  --verbose
```

### Server Hostname Mapping

The scanner includes friendly hostname mapping for convenience:

```python
SERVER_HOSTNAMES = {
    "willie": "mailcow.tailce791f.ts.net",
    "peter": "cp.quigs.com",
    "alfred": "localhost",
}
```

Pass friendly names (`--server willie`) and the scanner resolves to the actual hostname automatically.

### Compliance Scoring

**Formula:**
```
score = 100 - (critical × 20 + high × 10 + medium × 5 + low × 2)
score = GREATEST(0, LEAST(100, score))
```

**Thresholds:**
- **95-100**: Excellent (green)
- **80-94**: Good (yellow)
- **0-79**: Needs attention (red)

**Example Scores:**
- alfred (local): 100/100 - Perfect compliance
- peter (remote-ssh): 95/100 - 1 medium finding
- willie (aws-ec2): 80/100 - 2 high findings

### Database Queries

**View Latest Scans:**
```sql
SELECT server_name, server_type, scan_date, overall_score,
       findings_critical, findings_high, findings_medium, findings_low
FROM blueteam.v_latest_compliance_scans;
```

**View Active Findings:**
```sql
SELECT server_name, check_category, check_name, severity, finding_summary
FROM blueteam.v_active_compliance_findings
WHERE severity IN ('CRITICAL', 'HIGH')
ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 END;
```

**Calculate Compliance Score:**
```sql
SELECT blueteam.calculate_compliance_score(scan_id)
FROM blueteam.compliance_scans
WHERE server_name = 'willie'
ORDER BY scan_date DESC
LIMIT 1;
```

**Historical Stats:**
```sql
SELECT * FROM blueteam.get_compliance_stats(
    'willie',
    NOW() - INTERVAL '30 days',
    NOW()
);
```

### API Integration

**Endpoint:** `dashboard/api/compliance-scans.php`

**5 RESTful Endpoints:**

1. **Summary**: `GET ?action=summary`
   - Overall compliance across all servers

2. **Server Details**: `GET ?action=server&name=willie`
   - Detailed scan data for specific server

3. **Filtered Findings**: `GET ?action=findings&severity=high&category=ssh`
   - Query findings with filters

4. **Category Stats**: `GET ?action=categories`
   - Compliance stats by category

5. **Historical Trends**: `GET ?action=history&server=willie&days=30`
   - Historical compliance scores

**Authentication:** Requires `HTTP_X_AUTH_USER_ID` header

**Security Features:**
- Input validation (regex, whitelist, range checks)
- SQL injection prevention (prepared statements)
- Proper HTTP status codes (200, 400, 401, 404, 500)
- Error logging and handling

**Documentation:**
- `dashboard/api/COMPLIANCE_SCANS_API.md` - Complete API reference
- `dashboard/api/COMPLIANCE_SCANS_SUMMARY.md` - Implementation summary
- `dashboard/api/COMPLIANCE_SCANS_VERIFICATION.md` - Security verification (10/10)

### Test Results

**Comprehensive Testing:** `findings/COMPLIANCE_TEST_REPORT_2026-03-10.md` (532 lines)

**Tested Servers:**

| Server | Type | Score | Critical | High | Medium | Low | Status |
|--------|------|-------|----------|------|--------|-----|--------|
| alfred | local | 100.00 | 0 | 0 | 0 | 3 | ✅ PERFECT |
| peter | remote-ssh | 95.00 | 0 | 0 | 1 | 0 | ✅ EXCELLENT |
| willie | aws-ec2 | 80.00 | 0 | 2 | 0 | 0 | ✅ GOOD |

**Database Verification:**
- Total scans recorded: 3
- Total findings inserted: 36
- All views working correctly
- Score calculation accurate

**Performance:**
- alfred scan: 4 seconds
- peter scan: 8 seconds
- willie scan: 12 seconds

### AWS Features

**IMDSv2 Auto-Detection:**
```python
def get_ec2_metadata() -> Optional[Dict]:
    """Get EC2 instance metadata using IMDSv2."""
    # Token-based authentication
    # Auto-populates instance_id and region
    # 2-second timeout, graceful failure
```

**EBS Encryption Check:**
- Queries EC2 API for root volume encryption status
- Requires boto3 and AWS credentials

**Security Group Analysis:**
- Coming soon: Check for overly permissive rules
- Verify SSH restricted to specific IPs

### MailCow Integration

**Auto-Detection:**
- Detects `/opt/mailcow-dockerized/` directory
- Automatically runs MailCow checks on detected servers

**Container Version Check:**
```bash
cd /opt/mailcow-dockerized && git describe --tags
```
- Expected: "2026-01" or later
- Finding: Version mismatch if older

**SSL Certificate Check:**
```bash
echo | openssl s_client -servername email.northwoodsmail.com \
  -connect email.northwoodsmail.com:443 2>/dev/null | \
  openssl x509 -noout -enddate
```
- Severity: HIGH if < 30 days, CRITICAL if expired

**Docker Compose Health:**
```bash
docker ps --filter "name=mailcowdockerized" --format "{{.Status}}" | grep -c "Up"
```
- Expected: 15+ containers running
- Severity: CRITICAL if containers down

### Configuration

**Database Connection:**

File: `scripts/compliance-scanner.py` (lines 62-69)
```python
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "eqmon",
    "user": "eqmon"
    # Password from ~/.pgpass
}
```

**Setup ~/.pgpass:**
```bash
echo "localhost:5432:eqmon:eqmon:your_password" >> ~/.pgpass
chmod 600 ~/.pgpass
```

**AWS Credentials:**
- For EBS encryption checks, configure: `~/.aws/credentials`
- Or use EC2 instance profile
- Only needed for AWS-specific checks

### Troubleshooting

**SSH Connection Failed:**
```bash
# Test SSH manually
ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net echo 'test'

# Check hostname resolution
python3 -c "from scripts.compliance_scanner import SERVER_HOSTNAMES; print(SERVER_HOSTNAMES)"
```

**Database Connection Failed:**
```bash
# Test database
psql -h localhost -U eqmon -d eqmon -c "SELECT 1"

# Verify schema
psql -U eqmon -d eqmon -c "\dn blueteam"

# Check tables
psql -U eqmon -d eqmon -c "\dt blueteam.compliance*"
```

**AWS Checks Failing:**
```bash
# Verify boto3 installed
python3 -c "import boto3; print(boto3.__version__)"

# Test AWS credentials
aws sts get-caller-identity

# Check IMDSv2 metadata (on EC2)
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id
```

### Future Enhancements

**Planned Features:**
- CloudTrail logging verification
- VPC Flow Logs enabled check
- IAM password policy validation
- S3 bucket encryption audit
- RDS backup retention check
- Automated remediation scripts
- Dashboard UI integration
- Scheduled weekly scanning
- Email alerts on compliance failures

### Compliance Frameworks

**CIS Benchmarks:**
- CIS Ubuntu Linux 24.04 LTS Benchmark
- CIS Docker Benchmark 1.0

**AWS Frameworks:**
- AWS Foundational Security Best Practices
- AWS Well-Architected Framework (Security Pillar)

**NIST:**
- NIST Cybersecurity Framework (CSF)
  - PR.IP-4: Backups of information are conducted
  - PR.DS-2: Data-in-transit and data-at-rest are protected

---

## Lynis CIS Auditing

### Overview

**File:** `scripts/lynis-auditor.py` (256 lines)

Comprehensive CIS (Center for Internet Security) benchmark compliance auditing using the industry-standard Lynis security tool. Performs 200+ security tests and generates a hardening index score (0-100).

### Features

- **200+ Security Tests:** Comprehensive system security assessment
- **Hardening Index:** Overall security score (0-100)
- **CIS Benchmark Compliance:** Industry-standard security checks
- **Database Integration:** Historical tracking and trend analysis
- **Combined Security Posture:** Integrated with compliance scanner results
- **Finding Management:** Track warnings, suggestions, and resolutions

### Database Schema

**Tables:**
- `blueteam.lynis_audits` - Audit summary records with hardening index
- `blueteam.lynis_findings` - Individual warnings and suggestions

**Views:**
- `v_latest_lynis_audits` - Most recent audit per server
- `v_unresolved_lynis_findings` - All unresolved findings
- `v_lynis_hardening_trend` - Hardening index changes over time
- `v_security_posture` - **Combined compliance + Lynis scores**

**Functions:**
- `get_lynis_stats(server_name)` - Comprehensive statistics
- `resolve_lynis_finding(finding_id, notes)` - Mark finding as resolved

### Usage

**Run audit on local server:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
sudo bash scripts/run-lynis-audit.sh alfred
```

**Run audit on remote server:**
```bash
ssh willie
cd /opt/claude-workspace/projects/cyber-guardian
sudo bash scripts/run-lynis-audit.sh willie
```

**Audit all servers:**
```bash
for server in alfred willie peter; do
    echo "Auditing $server..."
    sudo bash scripts/run-lynis-audit.sh $server
done
```

### Output Example

```
================================================================================
LYNIS AUDIT SUMMARY
================================================================================
Server: alfred
Hardening Index: 78/100
Tests Performed: 219
Warnings: 12
Suggestions: 34
================================================================================
```

### Database Queries

**View latest audits:**
```sql
SELECT * FROM blueteam.v_latest_lynis_audits;
```

**View unresolved findings:**
```sql
SELECT * FROM blueteam.v_unresolved_lynis_findings
WHERE server_name = 'alfred'
ORDER BY severity;
```

**View combined security posture:**
```sql
SELECT
    server_name,
    compliance_score,
    lynis_hardening,
    combined_score
FROM blueteam.v_security_posture
ORDER BY combined_score DESC;
```

**Get comprehensive statistics:**
```sql
SELECT * FROM blueteam.get_lynis_stats('alfred');
```

**Mark finding as resolved:**
```sql
SELECT blueteam.resolve_lynis_finding(
    123,
    'Updated SSH configuration per recommendation'
);
```

### Hardening Index Interpretation

| Score | Rating | Description |
|-------|--------|-------------|
| 90-100 | Excellent | Very few improvements needed |
| 80-89 | Good | Minor hardening recommended |
| 70-79 | Fair | Several improvements recommended |
| 60-69 | Poor | Significant hardening needed |
| 0-59 | Critical | Major security concerns |

**Industry Benchmarks:**
- Production servers: Target 80+
- Development servers: Target 70+
- Personal systems: Target 60+

### Integration with Compliance Scanner

Lynis provides comprehensive CIS benchmark auditing that complements the compliance scanner:

**Compliance Scanner:**
- Focused configuration checks (SSH, firewall, Docker, AWS)
- Pass/fail binary results
- Automated daily/weekly scans

**Lynis Auditor:**
- Comprehensive system hardening assessment
- Hardening recommendations and best practices
- 200+ security tests
- Manual/scheduled execution

**Combined View:**
```sql
-- View integrated security posture
SELECT * FROM blueteam.v_security_posture;
```

### Automation

**Weekly Lynis audits via cron:**
```bash
# Add to crontab
0 2 * * 0 /opt/claude-workspace/projects/cyber-guardian/scripts/run-lynis-audit.sh alfred >> /var/log/lynis-cron.log 2>&1
```

### Documentation

**Complete documentation:** `docs/LYNIS_INTEGRATION.md`

Includes:
- Architecture overview
- Database schema details
- Installation instructions
- Usage examples
- Troubleshooting guide
- Remote server setup
- Performance metrics

---

## Log Parser

### Overview

**File:** `scripts/parse-malware-logs.py` (645 lines)

Python service that extracts scan results from log files and inserts them into PostgreSQL.

### Features

- **4 Scanner Parsers:** ClamAV, Maldet, RKHunter, Chkrootkit
- **Automatic Severity Assessment:** Critical, High, Medium, Low
- **Database Integration:** psycopg2 with transaction management
- **CLI Interface:** Dry-run mode, verbose logging
- **Error Handling:** Graceful failures, detailed logging

### Usage

```bash
# Parse all scanners for today
python3 parse-malware-logs.py

# Parse specific scanner
python3 parse-malware-logs.py --scanner clamav

# Parse specific date
python3 parse-malware-logs.py --scanner clamav --date 20260306

# Dry-run (no database insert)
python3 parse-malware-logs.py --dry-run --verbose
```

### Database Configuration

**File:** `parse-malware-logs.py` (lines 35-42)

```python
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "eqmon",
    "user": "eqmon"
    # Password from ~/.pgpass or environment
}
```

**Setup ~/.pgpass:**
```bash
echo "localhost:5432:eqmon:eqmon:your_password" >> ~/.pgpass
chmod 600 ~/.pgpass
```

### Severity Assessment

| Signature Pattern | Severity |
|-------------------|----------|
| backdoor, trojan, ransomware, rootkit | **Critical** |
| webshell, exploit, malware, worm | **High** |
| suspicious, adware, pua | **Medium** |
| test, heuristic | **Low** |

### Logging

**Parser logs to syslog:**
```bash
# View ClamAV parser logs
sudo journalctl -t clamav-parser -n 50

# View all parser logs
sudo journalctl -t *-parser --since today
```

---

## API Endpoints

### GET /api/malware.php

Returns comprehensive malware scan data.

**Authentication:** Requires `X-Auth-User-ID` header

**Response:**
```json
{
  "malware_score": 100.0,
  "latest_scans": [
    {
      "scan_type": "clamav",
      "scan_date": "2026-03-06 02:00:00",
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
    "clamav": 0.1,
    "maldet": 0.5,
    "rkhunter": 2.0,
    "chkrootkit": 2.0
  },
  "recent_scans": [...],
  "timestamp": "2026-03-06T02:30:00+00:00"
}
```

**Data Sections:**
1. **malware_score** - Real-time defense score (0-100)
2. **latest_scans** - Latest scan by each scanner type
3. **active_detections** - Unresolved malware findings
4. **severity_counts** - Count by severity level
5. **scan_stats** - 30-day statistics by scanner
6. **scan_history** - Daily scan aggregates
7. **last_scan_days** - Days since last scan per scanner
8. **recent_scans** - Last 10 scans across all types

### GET /api/posture.php

Security posture overview (updated to include malware score).

**Authentication:** Requires `X-Auth-User-ID` header

**Response:**
```json
{
  "current": {
    "overall": 87.5,
    "compliance": 92.0,
    "redteam": 85.0,
    "incident": 95.0,
    "monitoring": 80.0,
    "malware": 100.0
  },
  "history": [...]
}
```

**Score Weights:**
- Compliance: 30% (was 35%)
- Red Team: 25% (was 30%)
- Incident: 20%
- Monitoring: 15%
- **Malware: 10% (NEW)**

---

## Dashboard UI

### Malware Tab

**URL:** https://alfred.quigs.com/dashboard/security-dashboard/#malware

### Components

#### 1. Summary Cards (4 cards)

**Malware Defense Score:**
- Large score display (0-100)
- Shield icon 🛡️
- Color-coded (green ≥80, yellow ≥50, red <50)

**Scans Today:**
- Count of scans completed today
- Magnifying glass icon 🔍

**Active Threats:**
- Total unresolved detections
- Warning icon ⚠️
- Red background when > 0

**Files Scanned (24h):**
- Total files from last 24 hours
- Folder icon 📁
- Thousands separator formatting

#### 2. Latest Scan Results

**Scan Result Cards:**
- Grid layout (auto-fit)
- Color-coded left border:
  - Green: Clean
  - Red: Infected
  - Orange: Warning
- Metrics: Files scanned, infections, duration, last scan

#### 3. Active Detections Table

| Severity | File Path | Malware Signature | Detected | Scanner | Action |
|----------|-----------|-------------------|----------|---------|--------|
| Badge | Monospace path | Signature name | Timestamp | Type | Action taken |

**Features:**
- Severity badges (color-coded)
- Detection count badge in header
- "All clear!" empty state
- Sortable by severity (critical first)

#### 4. Scanner Status Grid

**4 Scanner Cards:**
- ClamAV, Maldet, RKHunter, Chkrootkit
- Last scan time
- Status indicators:
  - Green border: Active (< 7 days)
  - Orange border: Stale (≥ 7 days)
  - Gray: Never run

### Posture Tab Updates

**Malware Score Card:**
- Added as 5th score card
- Purple color scheme
- 10% weight label

**Updated Weights:**
- Compliance: 30% (was 35%)
- Red Team: 25% (was 30%)
- Incident: 20%
- Monitoring: 15%
- Malware: 10% (new)

### Responsive Design

**Breakpoints:**
- **Desktop (>768px):** 4-column summary cards
- **Tablet (≤768px):** 2-column summary cards
- **Mobile (≤480px):** Single-column layout

---

## Configuration

### Database Connection

**File:** `api/lib/db.php`

```php
function getSecurityDb(): PDO {
    return new PDO(
        'pgsql:host=localhost;dbname=eqmon',
        'eqmon',
        getenv('EQMON_AUTH_DB_PASS') ?: 'fallback_password'
    );
}
```

**Environment Variable:**
```bash
# Set in Apache config or .env file
export EQMON_AUTH_DB_PASS='your_password_here'
```

### Email Alerts

**Configure in scan scripts:**

File: `/usr/local/bin/clamav-daily-scan.sh`
```bash
ALERT_EMAIL="admin@quigs.com"

if [ $EXIT_CODE -eq 1 ]; then
    mail -s "⚠️ ClamAV: Malware Detected on $(hostname)" "$ALERT_EMAIL" < "$LOG_FILE"
fi
```

### Log Retention

**Configured in scan scripts:**
```bash
# Compress logs older than 7 days
find "$LOG_DIR" -name "clamav-*.log" -mtime +7 -exec gzip {} \;

# Delete compressed logs older than 30 days
find "$LOG_DIR" -name "clamav-*.log.gz" -mtime +30 -delete
```

### Cron Schedule

**File:** `/etc/cron.d/malware-scanning`

```cron
# ClamAV: Daily scan at 2:00 AM
0 2 * * * root /usr/local/bin/clamav-daily-scan.sh

# Maldet: Daily scan at 3:00 AM
0 3 * * * root /usr/local/bin/maldet-daily-scan.sh

# rkhunter: Weekly scan on Sundays at 4:00 AM
0 4 * * 0 root /usr/local/bin/rkhunter-weekly-scan.sh

# chkrootkit: Weekly scan on Sundays at 4:30 AM
30 4 * * 0 root /usr/local/bin/chkrootkit-weekly-scan.sh

# Update ClamAV definitions: Every 6 hours
0 */6 * * * root /usr/bin/freshclam --quiet

# Update maldet signatures: Daily at 1:00 AM
0 1 * * * root /usr/local/sbin/maldet --update 2>&1 | logger -t maldet-update

# Update rkhunter database: Daily at 1:30 AM
30 1 * * * root /usr/bin/rkhunter --update --quiet 2>&1 | logger -t rkhunter-update
```

---

## Testing

### Manual Test Workflow

**1. Run a scan:**
```bash
sudo /usr/local/bin/clamav-daily-scan.sh
```

**2. Check log created:**
```bash
ls -lh /var/log/malware-scans/clamav-*.log
```

**3. Verify parser ran:**
```bash
sudo journalctl -t clamav-parser -n 20
```

**4. Check database:**
```sql
PGPASSWORD='password' psql -h localhost -U eqmon -d eqmon <<'EOF'
SELECT * FROM blueteam.v_latest_scans WHERE scan_type='clamav';
SELECT blueteam.calculate_malware_score();
EOF
```

**5. Test API:**
```bash
curl -H "X-Auth-User-ID: 1" \
  http://localhost/dashboard/security-dashboard/api/malware.php | jq '.malware_score'
```

**6. Verify dashboard:**
- Visit: https://alfred.quigs.com/dashboard/security-dashboard/
- Click Malware tab
- Verify scan results display

### Test Malware Detection

**Create test file:**
```bash
# EICAR test virus (harmless test file)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
```

**Run scan:**
```bash
clamscan /tmp/eicar.com
```

**Expected:** Detection found, severity: low (test file)

**Cleanup:**
```bash
rm /tmp/eicar.com
```

### Verify Resolution Workflow

**Mark detection as resolved:**
```sql
UPDATE blueteam.malware_detections
SET resolved_at = NOW(),
    resolved_by = 'admin',
    resolution_notes = 'False positive - test file'
WHERE file_path = '/tmp/eicar.com';
```

**Verify score updates:**
```sql
SELECT blueteam.calculate_malware_score();
```

---

## Troubleshooting

### Database Connection Failed

**Symptom:** Parser or API returns "Database connection failed"

**Check:**
```bash
# Test connection
PGPASSWORD='password' psql -h localhost -U eqmon -d eqmon -c "SELECT 1"

# Verify schema exists
PGPASSWORD='password' psql -h localhost -U eqmon -d eqmon -c "\dn blueteam"

# Check tables exist
PGPASSWORD='password' psql -h localhost -U eqmon -d eqmon -c "\dt blueteam.*"
```

**Fix:**
- Verify PostgreSQL is running: `sudo systemctl status postgresql`
- Check password in `~/.pgpass` or `api/lib/db.php`
- Ensure `blueteam` schema exists: `CREATE SCHEMA IF NOT EXISTS blueteam;`

### Parser Not Inserting Data

**Symptom:** Scans complete but database not updated

**Check:**
```bash
# Verify parser script exists
ls -lh /opt/claude-workspace/shared-resources/scripts/parse-malware-logs.py

# Check parser logs
sudo journalctl -t clamav-parser -n 50

# Test parser manually
python3 /opt/claude-workspace/shared-resources/scripts/parse-malware-logs.py --dry-run --verbose
```

**Fix:**
- Install psycopg2: `pip install psycopg2-binary`
- Check database credentials in parser script
- Verify log files exist: `ls -lh /var/log/malware-scans/`

### API Returns Error

**Symptom:** API returns JSON error instead of data

**Check:**
```bash
# Test API directly with PHP
cd /var/www/html/alfred/dashboard/security-dashboard/api
php -r '$_SERVER["HTTP_X_AUTH_USER_ID"] = "1"; include "malware.php";'

# Check Apache error log
sudo tail -50 /var/log/apache2/error.log
```

**Common Issues:**
- **Timestamp casting error:** Fix in malware.php line 71-74 (see PHASE5_MANUAL_STEPS.md)
- **Column not found:** Verify view definitions match API queries
- **Authentication failed:** Check `X-Auth-User-ID` header

### Dashboard Not Loading

**Symptom:** Malware tab is blank or shows errors

**Check:**
```bash
# Browser console (F12)
# Look for JavaScript errors

# Verify files exist
ls -lh /var/www/html/alfred/dashboard/security-dashboard/index.php
ls -lh /var/www/html/alfred/dashboard/security-dashboard/css/security.css
ls -lh /var/www/html/alfred/dashboard/security-dashboard/js/security.js
```

**Fix:**
- Clear browser cache (Ctrl+Shift+R)
- Check cache busting version strings
- Verify API endpoints are accessible

### Scanner Not Running

**Symptom:** No recent scans in database

**Check:**
```bash
# Verify cron jobs
crontab -l | grep malware

# Check scan scripts exist
ls -lh /usr/local/bin/*scan.sh

# View cron logs
sudo journalctl -u cron --since today | grep malware
```

**Fix:**
- Run setup script: `sudo bash setup-malware-scans-v2.sh admin@quigs.com`
- Verify scanners installed: `which clamscan maldet rkhunter chkrootkit`
- Check scan script permissions: `chmod +x /usr/local/bin/*scan.sh`

---

## Development

### Local Development Setup

**1. Clone repository:**
```bash
cd /opt/claude-workspace/projects
git clone https://github.com/Quig-Enterprises/cyber-guardian.git
cd cyber-guardian
```

**2. Create test database:**
```sql
CREATE DATABASE blueteam_test;
\c blueteam_test
CREATE SCHEMA blueteam;
```

**3. Deploy schema to test database:**
```bash
cd sql
DB_NAME=blueteam_test bash deploy-phase1.sh
```

**4. Test parser:**
```bash
python3 ../scripts/parse-malware-logs.py --dry-run --verbose
```

### Making Changes

**Database Schema:**
1. Edit `sql/01-malware-schema.sql`
2. Test deployment: `DB_NAME=blueteam_test bash deploy-phase1.sh`
3. Verify: `psql -d blueteam_test -c "\dt blueteam.*"`

**Log Parser:**
1. Edit `scripts/parse-malware-logs.py`
2. Test: `python3 parse-malware-logs.py --dry-run --verbose`
3. Verify database insertion on real logs

**API Endpoints:**
1. Edit `api/malware.php` or `api/posture.php`
2. Test: `php -r '$_SERVER["HTTP_X_AUTH_USER_ID"] = "1"; include "malware.php";'`
3. Verify JSON output

**Dashboard UI:**
1. Edit `index.php`, `security.css`, or `security.js`
2. Increment cache-busting version string
3. Test in browser with DevTools (F12)

### Git Workflow

```bash
# Make changes
git add .

# Commit with descriptive message
git commit -m "Description of changes

- Detailed list of modifications
- Why the changes were needed
- Any breaking changes

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"

# Push to GitHub
git push origin main
```

### Code Style

**SQL:**
- Use uppercase for keywords: `SELECT`, `FROM`, `WHERE`
- Indent 4 spaces
- Schema-qualify all table names: `blueteam.table_name`

**Python:**
- PEP 8 compliance
- Docstrings for all classes and functions
- Type hints where appropriate

**PHP:**
- PSR-12 coding standard
- Prepared statements for all database queries
- HTML escaping for all output

**JavaScript:**
- Vanilla JS (no frameworks)
- `escapeHtml()` for all dynamic content
- Consistent indentation (2 spaces)

---

## Performance

### Query Optimization

**Indexes created:**
- `idx_malware_scans_type_date` - Fast latest scan lookup
- `idx_malware_detections_unresolved` - Active detections
- `idx_malware_detections_severity` - Severity filtering

**Result limiting:**
- Active detections: LIMIT 100
- Recent scans: LIMIT 10
- Scan history: 30-day window

### API Response Times

| Endpoint | Typical Response | Data Size |
|----------|------------------|-----------|
| /api/malware.php | <100ms | 2-25KB |
| /api/posture.php | <50ms | 1-5KB |

### Database Statistics

**Estimated storage:**
- 1 scan record: ~1KB
- 1 detection record: ~500 bytes
- 30 days of daily scans (4 scanners): ~120KB
- Conservative 1-year estimate: <1MB

---

## Security

### Authentication

- All API endpoints require `X-Auth-User-ID` header
- Session-based authentication via existing dashboard
- No API keys or tokens exposed to clients

### SQL Injection Prevention

- PDO prepared statements
- Parameterized queries
- No dynamic SQL construction
- `PDO::ATTR_EMULATE_PREPARES = false`

### XSS Prevention

- All dynamic content escaped via `escapeHtml()`
- No `eval()` or `innerHTML` with user data
- Content-Security-Policy headers (inherited from dashboard)

### Database Security

- Schema isolation (`blueteam` namespace)
- Principle of least privilege
- Password not in source code (environment variable or .pgpass)
- Connection encryption supported

### File Security

- Log files: `chmod 644` (readable by parser)
- Scripts: `chmod 755` (executable by root)
- API files: `www-data:www-data` ownership
- No executable permissions on data files

---

## Security Assessments

### Willie (MailCow Server)

**Assessment Date:** 2026-03-09 to 2026-03-10
**Assessment Type:** AWS-Compliant CVE & Security Scan
**Target:** willie (email.northwoodsmail.com / mailcow.tailce791f.ts.net)

#### Executive Summary

**Initial Security Rating:** 8/10 (GOOD)
**Current Security Rating:** 9.2/10 (EXCELLENT)

**Findings Location:** `/opt/claude-workspace/projects/cyber-guardian/findings/willie/`

#### Documents

- **willie-cve-scan-2026-03-09.md** - Initial CVE assessment (360 lines)
- **MITIGATION_PLAN.md** - 90-day remediation roadmap (436 lines)
- **MITIGATION_STATUS_2026-03-10.md** - Implementation progress tracking
- **README.md** - Executive summary

#### Assessment Results

**System Health:**
- ✅ Zero pending Ubuntu security updates
- ✅ Unattended-upgrades configured (3 AM UTC auto-reboot)
- ✅ Modern kernel: 6.14.0-1016-aws
- ✅ Modern Docker: 27.5.1
- ✅ AWS Backup configured (5 AM daily, 35-day retention)

**Initial CVE Findings (2026-03-09):**
- Total: 1,132 CVEs (153 CRITICAL, 979 HIGH)
- Critical containers:
  - SOGo 1.133: 527 CVEs
  - Dovecot 2.34: 120 CVEs
  - Postfix 1.80: 74 CVEs
  - PHP-FPM 1.93: 57 CVEs

**Critical Issues Identified:**
1. ofelia container using `:latest` tag (unpredictable updates)
2. No CVE scanning implemented
3. 1,132 known vulnerabilities across 16 containers

#### Mitigations Completed

**Phase 1 (2026-03-10):**
- ✅ MIT-WILLIE-001: Pinned ofelia container to v0.3.21
- ✅ MIT-WILLIE-002: Installed Trivy 0.69.3 and scanned all 16 containers

**Phase 2 (2026-03-10):**
- ✅ MIT-WILLIE-003: Updated MailCow from 2025-07 to 2026-01

#### Update Results

**MailCow 2026-01 Update (250 commits, 6-month jump):**

Major container updates:
- SOGo: 1.133 → 5.12.4-1
- Dovecot: 2.34 → 2.3.21.1-1
- Postfix: 1.80 → 3.7.11-1
- Rspamd: 2.2 → 3.14.2
- PHP-FPM: 1.93 → 8.2.29-1
- Nginx: 1.03 → 1.05
- Redis: 7.4.2-alpine → 7.4.6-alpine

**CVE Reduction:**
- Total CVEs: 1,132 → 483 (**57% reduction**, 649 CVEs resolved)
- CRITICAL CVEs: 153 → ~50 (**67% reduction**)
- HIGH CVEs: 979 → ~433 (**56% reduction**)

**Top Container Improvements:**
- Dovecot: 120 → 6 CVEs (**95% reduction**)
- PHP-FPM: 57 → 13 CVEs (**77% reduction**)
- SOGo: 527 → 189 CVEs (**64% reduction**, 338 CVEs resolved)
- Postfix: 74 → 36 CVEs (**51% reduction**)

#### Security Improvements

**Before Mitigation:**
- 🔴 ofelia using :latest tag (unpredictable)
- 🔴 No CVE visibility (unknown vulnerabilities)
- 🔴 1,132 total CVEs (153 CRITICAL, 979 HIGH)
- Security Rating: 8/10

**After Mitigation:**
- ✅ ofelia pinned to v0.3.21 (stable)
- ✅ Full CVE visibility (Trivy scanner operational)
- ✅ 649 CVEs resolved via MailCow update
- ✅ 483 remaining CVEs (~50 CRITICAL, ~433 HIGH)
- Security Rating: **9.2/10**

#### Pending Mitigations

**AWS Compliance Verification (Week 2):**
- Verify EC2 IMDSv2 enforcement
- Verify EBS encryption status
- Harden security groups (restrict SSH to Tailscale)

**System Hardening (Week 3-4):**
- Run Lynis CIS benchmark audit
- Install AIDE file integrity monitoring
- Set up automated weekly Trivy scanning

#### Tools Deployed

**Trivy Container Scanner:**
- Version: 0.69.3
- Database: 924 MB (main + Java DB)
- Scan location: `/home/ubuntu/trivy-scans/`
- Results archived: `findings/willie/trivy-scans/`

**Automated Scanning:**
- Script: `/home/ubuntu/scan-all-mailcow.sh`
- Target: All 16 MailCow containers
- Severity: HIGH and CRITICAL CVEs only

#### Timeline

- **2026-03-09:** Initial CVE assessment completed
- **2026-03-09:** Mitigation plan created (90-day roadmap)
- **2026-03-10 04:37:** Phase 1 complete (ofelia pin, Trivy install)
- **2026-03-10 04:55:** Phase 2 complete (MailCow 2026-01 update)
- **Total time:** 18 minutes for critical mitigations
- **CVE reduction:** 649 vulnerabilities resolved

#### References

- Assessment: `findings/willie/willie-cve-scan-2026-03-09.md`
- Mitigation Plan: `findings/willie/MITIGATION_PLAN.md`
- Status Report: `findings/willie/MITIGATION_STATUS_2026-03-10.md`
- Scan Results: `findings/willie/trivy-scans/` (16 container reports)
- Configuration: `config_willie_mailcow.yaml`
- Scan Script: `scripts/scan-willie-mailcow.sh`

---

## License

**Proprietary - Quig Enterprises**

Copyright © 2026 Quig Enterprises. All rights reserved.

This software and associated documentation are proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

---

## Support

### Documentation

- **Database:** `sql/README.md`
- **Parser:** `scripts/PHASE2_README.md`
- **API:** `api/PHASE3_README.md`
- **UI:** `dashboard/PHASE4_README.md`
- **Testing:** `/tmp/PHASE5_MANUAL_STEPS.md`

### Logs

**Parser logs:**
```bash
sudo journalctl -t clamav-parser -n 50
sudo journalctl -t maldet-parser -n 50
sudo journalctl -t rkhunter-parser -n 50
sudo journalctl -t chkrootkit-parser -n 50
```

**Scan logs:**
```bash
ls -lh /var/log/malware-scans/
tail -100 /var/log/malware-scans/clamav-*.log
```

**System logs:**
```bash
sudo journalctl -u cron --since today | grep malware
sudo tail -50 /var/log/apache2/error.log
```

### Contact

For issues, questions, or support:
- **Email:** admin@quigs.com
- **Repository:** https://github.com/Quig-Enterprises/cyber-guardian

---

**Version:** 1.3.0
**Last Updated:** 2026-03-10
**Maintainer:** Quig Enterprises Security Team
