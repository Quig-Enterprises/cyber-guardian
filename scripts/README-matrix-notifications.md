# Cyber-Guardian Matrix Notifications

**Version:** 1.0.0
**Date:** 2026-03-11

## Overview

Automated Matrix notifications for CRITICAL and HIGH severity security findings. Posts each finding as a separate message to `#cyber-guardian:artemis-matrix.ecoeyetech.com` with appropriate bot mentions based on affected server.

## Features

- **Severity Filtering:** Only sends CRITICAL and HIGH findings (configurable)
- **Separate Messages:** Each finding posted individually for better readability
- **Bot Mentions:** Automatically tags relevant bot based on server:
  - Artemis → `@artemis:artemis-matrix.ecoeyetech.com`
  - Willie, Peter, Alfred → `@alfred-bot:artemis-matrix.ecoeyetech.com`
- **Multiple Report Types:** Supports codebase scans, compliance scans, WordPress log scans
- **Formatted Messages:** Clear severity indicators and structured information

## Usage

### Manual Notification

```bash
# Send codebase scan findings
python3 send-to-matrix.py --scan-report reports/codebase-security-scan-*.json

# Send compliance scan findings
python3 send-to-matrix.py --compliance-report reports/compliance-*.json

# Send WordPress log vulnerabilities
python3 send-to-matrix.py --wp-log-report reports/wordpress-log-scan-*.json

# Send all types in one run
python3 send-to-matrix.py \
  --scan-report reports/codebase-security-scan-*.json \
  --compliance-report reports/compliance-*.json \
  --wp-log-report reports/wordpress-log-scan-*.json
```

### Dry Run Testing

```bash
# Preview messages without sending
python3 send-to-matrix.py --scan-report /path/to/report.json --dry-run
```

### Severity Filtering

```bash
# Send CRITICAL only
python3 send-to-matrix.py --scan-report report.json --min-severity CRITICAL

# Send MEDIUM and above
python3 send-to-matrix.py --scan-report report.json --min-severity MEDIUM
```

## Automated Integration

### Hourly Security Scan

The script is integrated into `hourly-security-scan.sh` and runs automatically after each scan:

```bash
# After codebase scan
python3 scripts/send-to-matrix.py --scan-report "$LATEST_JSON" --min-severity HIGH

# After WordPress log scan (if vulnerabilities found)
python3 scripts/send-to-matrix.py --wp-log-report "$WP_LOG_REPORT"
```

**Frequency:** Every hour for codebase scans, every 6 hours for WordPress log scans

## Message Formats

### Codebase Security Finding

```
**[CRITICAL] SQL Injection**
Unsanitized user input in database query

User-supplied data is directly concatenated into SQL query without escaping or parameterization

**Location:** `blueteam/api/user_search.py`:45
**Server:** alfred

@alfred-bot:artemis-matrix.ecoeyetech.com
```

### Compliance Finding

```
**[HIGH] Compliance: SSH-001**
Root login enabled over SSH

**Finding:** SSH configuration allows direct root login, violating security baseline

**Recommendation:** Set PermitRootLogin=no in /etc/ssh/sshd_config

**Server:** peter

@alfred-bot:artemis-matrix.ecoeyetech.com
```

### WordPress Log Exposure

```
**[HIGH] WordPress Log Exposure**
Publicly accessible log file detected

**Domain:** example.com
**Path:** `/wp-content/uploads/cxq-antispam-fallback.log`
**URL:** https://example.com/wp-content/uploads/cxq-antispam-fallback.log

**Recommendation:** Add .htaccess protection to wp-content/uploads/

**Server:** peter

@alfred-bot:artemis-matrix.ecoeyetech.com
```

## Configuration

### Environment Variables

Required in `.env` file:

```bash
MATRIX_HOMESERVER=http://localhost:8008
MATRIX_BOT_TOKEN=syt_YWxmcmVkLWJvdA_UsFnXwgxBSZivemMdfxM_0SQntK
```

### Matrix Room

Default room: `#cyber-guardian:artemis-matrix.ecoeyetech.com`

Override with `--room` argument:

```bash
python3 send-to-matrix.py --scan-report report.json --room "#incidents:artemis-matrix.ecoeyetech.com"
```

### Bot Mentions

Configured in `send-to-matrix.py`:

```python
BOT_MENTIONS = {
    "artemis": "@artemis:artemis-matrix.ecoeyetech.com",
    "willie": "@alfred-bot:artemis-matrix.ecoeyetech.com",
    "peter": "@alfred-bot:artemis-matrix.ecoeyetech.com",
    "alfred": "@alfred-bot:artemis-matrix.ecoeyetech.com",
}
```

## Rate Limiting

The script includes automatic rate limiting:
- 0.5 second delay between messages
- Prevents Matrix server rate limit errors
- Allows bots time to process mentions

## Severity Threshold

Current threshold: **HIGH** (includes CRITICAL and HIGH)

**Rationale:** Focus on actionable findings that require immediate attention. Once CRITICAL/HIGH findings are largely resolved, can lower to MEDIUM.

**To change threshold:**

Edit `hourly-security-scan.sh`:

```bash
# Change from HIGH to MEDIUM
python3 scripts/send-to-matrix.py --scan-report "$LATEST_JSON" --min-severity MEDIUM
```

## Error Handling

- Non-blocking: Scan continues even if Matrix notification fails
- Logged: All errors logged to `.scan-state/matrix-notify.log`
- Email fallback: Email alerts still sent regardless of Matrix status

## Logs

View Matrix notification logs:

```bash
# Real-time monitoring
tail -f .scan-state/matrix-notify.log

# Recent activity
tail -50 .scan-state/matrix-notify.log

# Search for failures
grep -i error .scan-state/matrix-notify.log
```

## Testing

### Test with Sample Data

```bash
# Create test findings
cat > /tmp/test-findings.json <<'EOF'
{
  "summary": {"critical": 1, "high": 1},
  "issues": [
    {
      "severity": "CRITICAL",
      "category": "SQL Injection",
      "title": "Test finding",
      "description": "This is a test",
      "file": "test.py",
      "line": "42"
    }
  ]
}
EOF

# Dry run
python3 send-to-matrix.py --scan-report /tmp/test-findings.json --dry-run

# Send to Matrix
python3 send-to-matrix.py --scan-report /tmp/test-findings.json
```

### Verify Delivery

Check Matrix room:
- https://app.element.io/#/room/#cyber-guardian:artemis-matrix.ecoeyetech.com
- Look for messages with severity indicators
- Verify bot mentions are correct

## Troubleshooting

### No Messages Sent

1. Check if findings meet severity threshold:
   ```bash
   jq '.summary.critical, .summary.high' report.json
   ```

2. Verify Matrix credentials:
   ```bash
   cat .env | grep MATRIX
   ```

3. Test connection:
   ```bash
   python3 -c "from lib.matrix_client import matrix_client; print('OK')"
   ```

### Bot Not Mentioned

Check server name detection:
```bash
grep -A5 "def get_bot_mention" scripts/send-to-matrix.py
```

Ensure finding includes correct server field.

### Rate Limit Errors

Increase delay between messages in `send_findings_to_matrix()`:

```python
time.sleep(1.0)  # Increase from 0.5 to 1.0 seconds
```

## Future Enhancements

**Planned features** (once CRITICAL/HIGH findings are largely resolved):

1. **Lower Threshold:** Include MEDIUM severity findings
2. **Grouping:** Batch similar findings into single message
3. **Thread Replies:** Use Matrix threads for related findings
4. **Reactions:** Automatically add reactions for status tracking
5. **Deduplication:** Skip already-reported persistent findings

## Related Files

- `scripts/send-to-matrix.py` - Main notification script
- `scripts/hourly-security-scan.sh` - Integration point
- `lib/matrix-client/matrix_client.py` - Matrix API wrapper
- `.env` - Matrix credentials (gitignored)

## Matrix Client Library

Uses custom `MatrixClient` wrapper from project-keystone:
- Supports federation via localhost:8008
- Automatic message formatting
- Metadata tagging for filtering
- Session attribution

See `lib/matrix-client/matrix_client.py` for API documentation.
