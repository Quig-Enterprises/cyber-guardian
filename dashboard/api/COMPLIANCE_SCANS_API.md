# Compliance Scans API Documentation

**File:** `/opt/claude-workspace/projects/cyber-guardian/dashboard/api/compliance-scans.php`
**Version:** 1.0.0
**Date:** 2026-03-10
**Status:** Production Ready

---

## Overview

RESTful API endpoint providing infrastructure compliance scanning data for the Cyber-Guardian security dashboard. This endpoint serves data from the compliance scanner system that audits AWS security configurations, OS-level security, and service-specific compliance.

**Note:** This is separate from `compliance.php` which handles NIST 800-171 controls compliance.

---

## Endpoints

### 1. Summary - Overall Compliance Status

**GET** `?action=summary`

Returns compliance summary across all monitored servers.

**Response:**
```json
{
  "overall_score": 85.50,
  "total_servers": 2,
  "total_findings": 12,
  "severity_totals": {
    "critical": 0,
    "high": 3,
    "medium": 5,
    "low": 4,
    "passing": 45
  },
  "servers": [
    {
      "server_name": "willie",
      "server_type": "aws-ec2",
      "latest_scan_date": "2026-03-10 00:36:14",
      "overall_score": 90.00,
      "critical_findings": 0,
      "high_findings": 1,
      "medium_findings": 2,
      "low_findings": 3,
      "passing_checks": 25,
      "total_findings": 6
    }
  ],
  "timestamp": "2026-03-10T00:40:00+00:00"
}
```

**Data Source:**
- `blueteam.v_compliance_summary_by_server` view
- `blueteam.v_latest_compliance_scans` view
- `blueteam.calculate_compliance_score()` function

---

### 2. Server Details - Individual Server Compliance

**GET** `?action=server&name={server_name}`

Returns detailed compliance data for a specific server including all findings with remediation steps.

**Parameters:**
- `name` (required) - Server name (alphanumeric, dash, underscore only)

**Example:** `?action=server&name=willie`

**Response:**
```json
{
  "scan": {
    "scan_id": 42,
    "server_name": "willie",
    "server_type": "aws-ec2",
    "scan_date": "2026-03-10 00:36:14",
    "scan_duration_seconds": 45,
    "overall_score": 90.00,
    "findings_critical": 0,
    "findings_high": 1,
    "findings_medium": 2,
    "findings_low": 3,
    "findings_pass": 25,
    "checks_total": 31,
    "checks_run": 31,
    "checks_skipped": 0,
    "metadata": {
      "region": "us-east-2",
      "instance_id": "i-xxxxxxxxx",
      "scanner_version": "1.0.0"
    }
  },
  "findings": [
    {
      "finding_id": 123,
      "check_category": "aws",
      "check_name": "EBS Volume Encryption",
      "check_id": "aws-ebs-encryption",
      "status": "fail",
      "severity": "high",
      "finding_summary": "EBS volume is not encrypted",
      "finding_details": "Volume vol-xxxxxxxxx is not encrypted at rest",
      "remediation_steps": "Create encrypted snapshot, create volume from snapshot, attach to instance",
      "aws_resource_id": "vol-xxxxxxxxx",
      "aws_resource_type": "ebs",
      "file_path": null,
      "service_name": null,
      "cis_benchmark": null,
      "aws_foundational_security": "EC2.7",
      "nist_csf": null,
      "detected_at": "2026-03-10 00:36:14",
      "resolved_at": null,
      "resolved_by": null,
      "resolution_notes": null,
      "resolved": false
    }
  ],
  "timestamp": "2026-03-10T00:40:00+00:00"
}
```

**Data Source:**
- `blueteam.v_latest_compliance_scans` view
- `blueteam.compliance_findings` table

**Error Responses:**
- `400 Bad Request` - Missing or invalid server name
- `404 Not Found` - Server not found or no scans available

---

### 3. Findings - Filtered Active Findings

**GET** `?action=findings&severity={severity}&category={category}&server={name}`

Returns active (unresolved) findings with optional filters.

**Parameters (all optional):**
- `severity` - Filter by severity: `critical`, `high`, `medium`, `low`
- `category` - Filter by check category: `aws`, `os`, `ssh`, `docker`, `wordpress`, etc.
- `server` - Filter by server name

**Example:** `?action=findings&severity=high&category=aws`

**Response:**
```json
{
  "filters": {
    "severity": "high",
    "category": "aws",
    "server": null
  },
  "total_findings": 2,
  "findings": [
    {
      "finding_id": 123,
      "server_name": "willie",
      "server_type": "aws-ec2",
      "check_category": "aws",
      "check_name": "EBS Volume Encryption",
      "check_id": "aws-ebs-encryption",
      "severity": "high",
      "finding_summary": "EBS volume is not encrypted",
      "finding_details": "Volume vol-xxxxxxxxx is not encrypted at rest",
      "remediation_steps": "Create encrypted snapshot...",
      "aws_resource_id": "vol-xxxxxxxxx",
      "aws_resource_type": "ebs",
      "file_path": null,
      "service_name": null,
      "cis_benchmark": null,
      "aws_foundational_security": "EC2.7",
      "nist_csf": null,
      "detected_at": "2026-03-10 00:36:14",
      "scan_date": "2026-03-10 00:36:14"
    }
  ],
  "timestamp": "2026-03-10T00:40:00+00:00"
}
```

**Data Source:**
- `blueteam.compliance_findings` table
- `blueteam.compliance_scans` table
- Filtered for `status = 'fail'` AND `resolved_at IS NULL`

**Limit:** 500 findings per request

**Error Responses:**
- `400 Bad Request` - Invalid filter parameter format

---

### 4. Categories - Compliance by Category

**GET** `?action=categories`

Returns compliance statistics grouped by check category.

**Response:**
```json
{
  "categories_by_server": {
    "willie": [
      {
        "check_category": "aws",
        "critical": 0,
        "high": 2,
        "medium": 1,
        "low": 1,
        "pass": 10,
        "total_checks": 14,
        "pass_rate": 71.43
      },
      {
        "check_category": "ssh",
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
        "pass": 5,
        "total_checks": 7,
        "pass_rate": 71.43
      }
    ]
  },
  "all_categories": [...],
  "timestamp": "2026-03-10T00:40:00+00:00"
}
```

**Data Source:**
- `blueteam.v_compliance_by_category` view

---

### 5. History - Historical Compliance Trends

**GET** `?action=history&server={name}&days={n}`

Returns historical compliance scores for trend analysis.

**Parameters:**
- `server` (optional) - Filter by server name
- `days` (optional) - Number of days to retrieve (1-365, default: 30)

**Example:** `?action=history&server=willie&days=7`

**Response:**
```json
{
  "days": 7,
  "server_filter": "willie",
  "total_scans": 14,
  "history_by_server": {
    "willie": [
      {
        "server_name": "willie",
        "scan_date": "2026-03-03 00:36:14",
        "overall_score": 88.00,
        "findings_critical": 0,
        "findings_high": 2,
        "findings_medium": 3,
        "findings_low": 2,
        "findings_pass": 24,
        "checks_total": 31
      }
    ]
  },
  "all_history": [...],
  "timestamp": "2026-03-10T00:40:00+00:00"
}
```

**Data Source:**
- `blueteam.compliance_scans` table

**Error Responses:**
- `400 Bad Request` - Invalid days parameter (must be 1-365)

---

## Security Features

### Authentication
- Requires `HTTP_X_AUTH_USER_ID` header
- Returns `401 Unauthorized` if missing

### Input Validation
- Server names: Alphanumeric, dash, underscore only (`/^[a-zA-Z0-9_-]+$/`)
- Severity: Whitelist validation (`critical`, `high`, `medium`, `low`)
- Category: Alphanumeric, dash, underscore only
- Days: Integer range validation (1-365)

### SQL Injection Prevention
- All user inputs use prepared statements with parameter binding
- No raw SQL concatenation
- PDO configured with `PDO::ATTR_EMULATE_PREPARES => false`

### Error Handling
- Database errors logged via `error_log()`
- Generic error messages returned to client (no sensitive data leak)
- Appropriate HTTP status codes (400, 401, 404, 500)

### Data Type Safety
- Explicit type casting for all numeric values
- Consistent JSON response format
- Null value handling for optional fields

---

## Database Schema

### Tables
- `blueteam.compliance_scans` - Scan execution metadata
- `blueteam.compliance_findings` - Individual check results

### Views
- `blueteam.v_latest_compliance_scans` - Latest scan per server
- `blueteam.v_active_compliance_findings` - Unresolved findings
- `blueteam.v_compliance_summary_by_server` - Summary stats per server
- `blueteam.v_compliance_by_category` - Stats grouped by category

### Functions
- `blueteam.calculate_compliance_score()` - Score calculation (0-100)

---

## Testing

### Manual Testing

```bash
# Summary endpoint
curl -H "X-Auth-User-ID: test-user" \
  "http://localhost/cyber-guardian/api/compliance-scans.php?action=summary"

# Server details
curl -H "X-Auth-User-ID: test-user" \
  "http://localhost/cyber-guardian/api/compliance-scans.php?action=server&name=willie"

# Filtered findings
curl -H "X-Auth-User-ID: test-user" \
  "http://localhost/cyber-guardian/api/compliance-scans.php?action=findings&severity=high"

# Categories
curl -H "X-Auth-User-ID: test-user" \
  "http://localhost/cyber-guardian/api/compliance-scans.php?action=categories"

# History
curl -H "X-Auth-User-ID: test-user" \
  "http://localhost/cyber-guardian/api/compliance-scans.php?action=history&server=willie&days=7"
```

### Expected Behaviors

**Success Response:**
- HTTP 200
- Valid JSON
- Includes `timestamp` field in ISO 8601 format

**Authentication Failure:**
- HTTP 401
- `{"error":"Unauthorized"}`

**Invalid Parameters:**
- HTTP 400
- `{"error":"..."}`

**Database Error:**
- HTTP 500
- `{"error":"Database connection failed"}` or `{"error":"Database query failed"}`

---

## Integration Notes

### Database Connection
Uses `lib/db.php` which:
- Reads credentials from `.env` file
- Connects to `alfred_admin` database via `127.0.0.1`
- Uses `blueteam` schema

### CORS Headers
None added by default. Add if needed for cross-origin requests:
```php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: X-Auth-User-ID, Content-Type');
```

### Frontend Integration
Designed for use with Cyber-Guardian security dashboard:
- Load summary on dashboard page load
- Display server-specific details on click
- Filter findings by severity/category
- Show category breakdown in charts
- Plot historical trends

---

## Compliance Framework Mapping

### Supported Frameworks
- **CIS Benchmarks** - `cis_benchmark` field
- **AWS Foundational Security** - `aws_foundational_security` field
- **NIST CSF** - `nist_csf` field

### Check Categories
- `aws` - AWS infrastructure (IMDSv2, EBS encryption, security groups)
- `os` - Operating system security (patches, kernel settings)
- `ssh` - SSH configuration (root login, key auth, password auth)
- `docker` - Container security
- `wordpress` - WordPress hardening
- `mailcow` - Mail server security

---

## Maintenance

### Adding New Endpoints
1. Add case to main switch statement
2. Create handler function following naming convention
3. Document in this file
4. Add test examples

### Performance Optimization
- Views are pre-aggregated for efficiency
- Queries use indexes on scan_id, server_name, status, severity
- LIMIT clauses prevent excessive data transfer

### Monitoring
- Check error logs for database connection failures
- Monitor API response times
- Track most-used endpoints for optimization

---

## Version History

**1.0.0 (2026-03-10)**
- Initial production release
- 5 endpoints: summary, server, findings, categories, history
- Input validation and SQL injection prevention
- Full documentation

---

## Related Documentation

- `/opt/claude-workspace/projects/cyber-guardian/sql/02-compliance-schema.sql` - Database schema
- `/opt/claude-workspace/projects/cyber-guardian/dashboard/api/lib/db.php` - Database connection
- `compliance.php` - NIST 800-171 controls (different system)
