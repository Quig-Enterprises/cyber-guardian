# Keystone Dashboard Integration for Lynis

**Version:** 1.0.0
**Date:** 2026-03-10
**Status:** Production Ready

---

## Overview

The Lynis security audit system is now integrated into the Project Keystone admin dashboard, providing web-based configuration and monitoring of automated security audits.

**Access URL:** https://8qdj5it341kfv92u.brandonquig.com/admin/lynis-config.php

**Authentication:** Requires Keystone admin or super user role

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                  Project Keystone Dashboard                  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Admin Panel (lynis-config.php)                       │  │
│  │  - JavaScript UI                                      │  │
│  │  - Real-time status display                           │  │
│  │  - Schedule configuration form                        │  │
│  │  - Manual audit trigger                               │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│                    HTTPS Requests                            │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Cyber-Guardian API (schedule.php)                    │  │
│  │  - GET  /schedule      → Read cron schedule           │  │
│  │  - POST /schedule      → Update cron                  │  │
│  │  - POST /run-now       → Trigger immediate audit      │  │
│  │  - GET  /status        → Audit status + posture       │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│              Manages Crontab + Database                      │
└─────────────────────────────────────────────────────────────┘
```

### Authentication Flow

1. User accesses `/admin/lynis-config.php` via Keystone dashboard
2. Keystone middleware verifies session and admin role
3. Page loads with JavaScript that makes API calls
4. API calls go to `/cyber-guardian/api/schedule.php`
5. Nginx intercepts and validates via `auth_request` to Keystone
6. User identity headers injected: `X-Auth-User-ID`, `X-Auth-User-Name`
7. API executes with authenticated user context
8. Results returned as JSON

**Security:** All API endpoints are protected by Keystone's centralized authentication. No unauthenticated access is possible.

---

## Files Created/Modified

### New Files

1. **API Endpoint**
   - Path: `/opt/claude-workspace/projects/cyber-guardian/api/schedule.php`
   - Purpose: RESTful API for Lynis schedule management
   - Database: Connects to `eqmon` database for audit status
   - Cron Management: Direct crontab manipulation via `crontab -l` and `crontab` commands

2. **Admin Page**
   - Path: `/var/www/html/project-keystone/dashboard/admin/lynis-config.php`
   - Purpose: Web UI for Lynis configuration
   - Features: Schedule config, status display, manual trigger
   - Design: Follows Keystone admin panel design patterns

### Modified Files

1. **Nginx Configuration**
   - File: `/etc/nginx/sites-available/finance-manager.conf`
   - Added: Location block for `/cyber-guardian/api/*.php`
   - Protection: Keystone `auth_request` integration
   - PHP-FPM: Unix socket execution with user headers

2. **Keystone Admin Header**
   - File: `/var/www/html/project-keystone/dashboard/admin/lib/header.php`
   - Added: Navigation link to "Lynis" page
   - Permission: Visible to admin and super users only

---

## API Endpoints

### 1. GET /schedule

**Purpose:** Retrieve current Lynis cron schedule

**Response:**
```json
{
  "enabled": true,
  "frequency": "weekly",
  "time": "02:00",
  "day_of_week": "0",
  "day_of_month": "*",
  "cron_expression": "0 2 * * 0",
  "raw_line": "0 2 * * 0 /path/to/script >> /path/to/log 2>&1"
}
```

**Frequency Values:**
- `daily` - Every day
- `weekly` - Every Sunday
- `monthly` - First of month
- `custom` - Non-standard cron expression
- `disabled` - No cron job found

### 2. POST /schedule

**Purpose:** Update Lynis cron schedule

**Request Body:**
```json
{
  "frequency": "weekly",
  "time": "02:00"
}
```

**Valid Frequencies:**
- `daily` - Every day at specified time
- `weekly` - Every Sunday at specified time
- `monthly` - First of month at specified time
- `disabled` - Remove cron job entirely

**Time Format:** `HH:MM` (24-hour format)

**Response:**
```json
{
  "success": true,
  "message": "Schedule updated to weekly at 02:00",
  "frequency": "weekly",
  "time": "02:00",
  "cron_expression": "0 2 * * 0 /path/to/script >> /path/to/log 2>&1"
}
```

**Error Response:**
```json
{
  "error": "Invalid frequency. Must be: daily, weekly, monthly, or disabled"
}
```

### 3. POST /run-now

**Purpose:** Trigger immediate Lynis audit on all servers

**Request:** No body required

**Response:**
```json
{
  "success": true,
  "message": "Audit started in background",
  "log_file": "/var/log/cyber-guardian/manual-audit-20260310152030.log",
  "started_at": "2026-03-10 15:20:30"
}
```

**Process:**
- Runs `audit-all-servers.sh` in background via `nohup`
- Output logged to timestamped file
- Returns immediately (non-blocking)
- Audit takes ~10-15 minutes for all three servers

### 4. GET /status

**Purpose:** Get current audit status and security posture

**Response:**
```json
{
  "last_run": "2026-03-10 10:11:58",
  "recent_audits": [
    {
      "server_name": "peter",
      "audit_date": "2026-03-10 10:11:58.186466",
      "hardening_index": 65,
      "tests_performed": 291,
      "warnings_count": 2,
      "suggestions_count": 60
    },
    ...
  ],
  "security_posture": [
    {
      "server_name": "alfred",
      "compliance_score": "100.00",
      "lynis_hardening": 64,
      "combined_score": "82.00"
    },
    ...
  ],
  "log_file": "/var/log/cyber-guardian/lynis-weekly-20260310.log"
}
```

**Data Sources:**
- `recent_audits` - Last 10 audits from `blueteam.lynis_audits`
- `security_posture` - Current scores from `blueteam.v_security_posture` view
- `last_run` - Filesystem modification time of most recent log
- `log_file` - Path to most recent weekly log file

---

## Admin Page Features

### Schedule Configuration

**Frequency Options:**
- Daily - Runs every day at specified time
- Weekly - Runs every Sunday at specified time (recommended)
- Monthly - Runs on the 1st of each month
- Disabled - Turns off automated scanning

**Time Selection:**
- 24-hour format (HH:MM)
- Default: 02:00 (2:00 AM)
- Recommended: Off-hours to minimize impact

**Update Button:**
- Saves configuration immediately
- Updates crontab for `ublirnevire` user
- Shows success/error toast notification

### Manual Audit Trigger

**"Run Audit Now" Button:**
- Triggers immediate audit on all servers
- Runs in background (non-blocking)
- Progress visible in logs
- Results appear in dashboard after completion (~10-15 minutes)

**Use Cases:**
- Test schedule configuration
- After server updates or configuration changes
- Before important events or audits
- After security incidents

### Security Posture Display

**Current Scores:**
- Server name (alfred, willie, peter)
- Combined score (compliance + Lynis average)
- Compliance scanner score
- Lynis hardening index

**Color Coding:**
- Green (≥80): Good security posture
- Yellow (70-79): Warning - needs improvement
- Red (<70): Danger - immediate attention required

**Auto-Refresh:**
- Status updates every 30 seconds
- No page reload required
- Real-time visibility during manual audits

### Recent Audits Table

**Columns:**
- Server name
- Audit date/time
- Hardening index (0-100)
- Tests performed
- Warnings count
- Suggestions count

**Displays:** Last 10 audits across all servers

**Sorting:** Most recent first

---

## Usage Examples

### Change Schedule to Daily

1. Navigate to https://8qdj5it341kfv92u.brandonquig.com/admin/lynis-config.php
2. Select "Daily" from Frequency dropdown
3. Set desired time (e.g., "03:00" for 3:00 AM)
4. Click "Update Schedule"
5. Toast notification confirms change
6. Current Schedule section updates to reflect new cron

### Run Manual Audit

1. Navigate to Lynis configuration page
2. Click "Run Audit Now" button
3. Confirm action in dialog
4. Toast notification: "Audit started successfully"
5. Wait ~10-15 minutes for completion
6. Security Posture and Recent Audits sections auto-update

### Disable Automated Scanning

1. Navigate to Lynis configuration page
2. Select "Disabled" from Frequency dropdown
3. Click "Update Schedule"
4. Cron job removed from crontab
5. Current Schedule shows "Status: Disabled"
6. Manual audits still available via "Run Audit Now"

---

## Permissions

### Required Roles

**Access to Admin Page:**
- Keystone admin role on `admin` service
- Keystone super user

**Access to API:**
- Same as admin page (enforced via `auth_request`)
- Unauthenticated requests receive 401 Unauthorized
- Redirected to Keystone login page

### Crontab Permissions

**Current User:** `ublirnevire`

**Crontab Access:**
- Read via `crontab -l`
- Write via `crontab <file>`
- No sudo required (user's own crontab)

**Script Execution:**
- Owned by `ublirnevire`
- Passwordless sudo for Lynis commands (via `/etc/sudoers.d/90-lynis-cyber-guardian`)
- SSH keys for remote server access

---

## Nginx Configuration

```nginx
# Cyber-Guardian API — protected by Keystone auth_request
location ~ ^/cyber-guardian/api/(.+\.php)$ {
    auth_request /_keystone_auth;
    error_page 401 = @keystone_login;
    auth_request_set $auth_user_id    $upstream_http_x_user_id;
    auth_request_set $auth_user_name  $upstream_http_x_user_name;
    auth_request_set $auth_user_super $upstream_http_x_user_super;

    include fastcgi_params;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    fastcgi_param SCRIPT_FILENAME /opt/claude-workspace/projects/cyber-guardian/api/$1;
    fastcgi_param DOCUMENT_ROOT /opt/claude-workspace/projects/cyber-guardian;
    fastcgi_param HTTP_X_AUTH_USER_ID $auth_user_id;
    fastcgi_param HTTP_X_AUTH_USER    $auth_user_name;
    fastcgi_param HTTP_X_AUTH_SUPER   $auth_user_super;
    fastcgi_hide_header X-Powered-By;
}
```

**Key Features:**
- `auth_request /_keystone_auth` - Validates session before execution
- User headers injected from Keystone response
- PHP-FPM execution with full user context
- Direct file path (no DocumentRoot traversal)

---

## Database Schema

The API queries the following database views and tables:

### Views Used

1. **blueteam.v_security_posture**
   - Combined security scores
   - Compliance + Lynis average
   - One row per server

2. **blueteam.lynis_audits**
   - Historical audit records
   - Full audit metadata
   - Finding counts

### Connection Details

**Database:** `eqmon`
**User:** `eqmon`
**Host:** `127.0.0.1` (local PostgreSQL)
**Schema:** `blueteam`

---

## Troubleshooting

### API Returns 401 Unauthorized

**Cause:** Not logged into Keystone dashboard

**Fix:**
1. Navigate to https://8qdj5it341kfv92u.brandonquig.com/admin/login.php
2. Log in with Keystone credentials
3. Return to Lynis configuration page

### Schedule Updates Fail

**Symptom:** "Failed to update crontab" error

**Possible Causes:**
1. Invalid cron syntax (API validation should prevent this)
2. Crontab command failed

**Debugging:**
```bash
# Check current crontab
crontab -l | grep lynis

# Verify script exists
ls -la /opt/claude-workspace/projects/cyber-guardian/scripts/weekly-audit-cron.sh

# Test crontab write manually
crontab -l > /tmp/test-cron
echo "# Test line" >> /tmp/test-cron
crontab /tmp/test-cron
crontab -l | tail -1
```

### Manual Audit Button Does Nothing

**Symptom:** Click "Run Audit Now" but no response

**Possible Causes:**
1. API call failing
2. Script execution error
3. Browser console errors

**Debugging:**
```bash
# Check API directly (from alfred server)
curl -H "X-Auth-User-ID: test-user" \
     http://localhost/cyber-guardian/api/schedule.php?action=run-now \
     -X POST

# Check if audit is running
ps aux | grep audit-all-servers

# Check logs
tail -f /var/log/cyber-guardian/manual-audit-*.log
```

**Browser Console:**
- Open DevTools (F12)
- Check Console tab for JavaScript errors
- Check Network tab for failed API calls

### Security Posture Not Updating

**Symptom:** Scores show old data or "Loading..."

**Possible Causes:**
1. Database connection issue
2. View query failing
3. No recent audits run

**Debugging:**
```bash
# Check database connection
psql postgresql://eqmon:PASSWORD@localhost/eqmon -c "SELECT version();"

# Check security posture view
psql postgresql://eqmon:PASSWORD@localhost/eqmon \
     -c "SELECT * FROM blueteam.v_security_posture ORDER BY server_name;"

# Check recent audits
psql postgresql://eqmon:PASSWORD@localhost/eqmon \
     -c "SELECT server_name, audit_date FROM blueteam.lynis_audits ORDER BY audit_date DESC LIMIT 5;"
```

---

## Future Enhancements

### Planned Features

**Email Notifications:**
- Configure email recipients via UI
- Alert on score degradation
- Weekly summary reports
- Immediate alerts for critical findings

**Server Selection:**
- Choose which servers to audit
- Per-server schedule configuration
- Selective manual audits

**Alert Thresholds:**
- Custom score thresholds per server
- Warning vs. critical levels
- Notification preferences

**Audit History:**
- Graphical trend charts
- Historical comparison
- Score degradation analysis
- Finding remediation tracking

**Advanced Scheduling:**
- Custom cron expressions
- Multiple schedules
- Blackout windows
- Maintenance mode

### Integration Opportunities

**Project Keystone Dashboard:**
- Security posture widget on main dashboard
- Quick status indicators
- One-click audit trigger from main page

**Cyber-Guardian Dashboard:**
- Dedicated Lynis section
- Finding drill-down
- Remediation workflow
- Compliance mapping

**Alerting Systems:**
- Slack/Discord notifications
- PagerDuty integration
- Email via SendGrid
- SMS alerts for critical issues

---

## Maintenance

### Weekly Tasks

**None required** - Fully automated

### Monthly Review

**Recommended:**
1. Review security posture trends
2. Verify all servers are being audited
3. Check for persistent findings
4. Update schedule if needed

### Quarterly Tasks

**Recommended:**
1. Review automation effectiveness
2. Audit user access to admin panel
3. Update alert thresholds if needed
4. Test manual audit trigger

---

## Security Considerations

### Authentication

**Keystone Integration:**
- Centralized authentication
- Session-based access control
- MFA support (if enabled in Keystone)
- Role-based permissions

**API Protection:**
- All endpoints behind `auth_request`
- No unauthenticated access possible
- User identity in all requests
- Audit trail via Keystone logs

### Cron Management

**User Context:**
- Crontab owned by `ublirnevire`
- No root access required
- Isolated from system crontab

**Script Permissions:**
- Scripts owned by `ublirnevire`
- Executable permissions required
- Passwordless sudo for Lynis only

### Database Access

**Connection:**
- Local PostgreSQL only (127.0.0.1)
- No remote access
- Credentials in API file (consider moving to .env)

**Queries:**
- Read-only SELECT statements for status
- No user input in SQL queries
- Parameterized queries (PDO)

---

## References

- Lynis Integration Docs: `/opt/claude-workspace/projects/cyber-guardian/docs/LYNIS_INTEGRATION.md`
- Automated Scanning Docs: `/opt/claude-workspace/projects/cyber-guardian/docs/AUTOMATED_SCANNING.md`
- Project Keystone: `/var/www/html/project-keystone/`
- Cyber-Guardian Project: `/opt/claude-workspace/projects/cyber-guardian/`
- Nginx Config: `/etc/nginx/sites-available/finance-manager.conf`

---

**Last Updated:** 2026-03-10
**Version:** 1.0.0
**Status:** Production Ready
**Access:** https://8qdj5it341kfv92u.brandonquig.com/admin/lynis-config.php
