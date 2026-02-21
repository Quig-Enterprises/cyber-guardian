# EMERGENCY: Server-Wide Failure
**Date:** February 20, 2026 16:25 CST
**Server:** cp.quigs.com
**Status:** 🔴 **CRITICAL - ALL WORDPRESS SITES DOWN**

---

## Executive Summary

**ALL WordPress sites on cp.quigs.com are experiencing complete HTTP timeouts.**

This is a **cascading server failure** affecting all 34+ WordPress installations. Issue began during PHP 8.3 upgrade and has escalated to complete server saturation.

---

## Timeline

- **15:40** - PHP 8.3 upgrade completed
- **15:45** - Server load spike to 40.54 (first sign of trouble)
- **15:50** - quigs.com isolated timeout
- **16:15** - quigs.com rolled back to PHP 8.2 (no improvement)
- **16:22** - **SERVER LOAD 72.10 - ALL SITES DOWN**
- **16:23** - Emergency PHP-FPM restart across all versions
- **16:25** - Load dropping but sites still unreachable
- **16:37** - Load at 23.64, sites still timing out

---

## Current Status

### Server Metrics
- **Load Average:** 23.64 (was 72.10, trending down)
- **PHP Processes:** 80 workers (multiple sites maxed out at 8 each)
- **MySQL:** ✅ Running normally (no stuck queries)
- **Apache:** ✅ Running
- **Nginx:** ✅ Running

### Affected Sites
- ❌ **ALL WordPress sites** (34+ installations)
- ✅ Non-WordPress services (likely OK)

### Sites Tested
- fcal-wis.org: ❌ TIMEOUT
- ainsworthwi.gov: ❌ TIMEOUT
- charliesbikeshop.com: ❌ TIMEOUT
- quigs.com: ❌ TIMEOUT
- pearsonpickerellions.org: ❌ TIMEOUT

---

## Root Cause Analysis

### Initial Trigger: PHP Version Upgrade
The PHP 8.3 upgrade triggered WordPress cron jobs and plugin initialization across ALL sites simultaneously.

### Cascading Failure Sequence

1. **PHP Upgrade (15:40)**
   - 40 sites upgraded to PHP 8.3
   - Apache/Nginx configurations regenerated
   - PHP-FPM pools restarted

2. **Mass WordPress Initialization (15:40-15:45)**
   - All WordPress sites attempted to load simultaneously
   - Cron jobs triggered on all sites
   - Plugin updates checked on all sites
   - External API calls (antispam, site manager, etc.)

3. **PHP-FPM Saturation (15:45-16:20)**
   - Worker pools maxed out (8 per site)
   - Processes stuck waiting for external resources
   - New requests queued indefinitely
   - Server load climbed to 72.10

4. **Complete Failure (16:20+)**
   - All sites unreachable
   - Even after PHP-FPM restart, same behavior
   - Suggests persistent issue (not just process saturation)

---

## Technical Evidence

### PHP-FPM Process Analysis (16:22)
```
Sites with maxed workers (8/8):
- quigs.com (8 workers at 9-10% CPU each)
- fcal-wis.org (8 workers at 8-9% CPU each)
- kettlebowl.org (8 workers at 7-8% CPU each)
- quigbooks.com (8 workers at 7-8% CPU each)
[...15 more sites affected...]
```

### Stuck Process Pattern
All processes showing identical behavior:
- Continuous CPU usage (7-19%)
- Running for 3-7 minutes
- Polling on file descriptors (waiting for response)
- Not terminating

### MySQL Status
✅ **HEALTHY**
- No stuck queries
- All connections in "Sleep" state
- Normal operation

---

## Why Sites Still Down After PHP-FPM Restart

### Hypothesis: Persistent External Resource Timeout

**Evidence:**
1. PHP-FPM restart cleared processes
2. New requests create new stuck processes
3. Pattern repeats immediately
4. MySQL healthy (not database issue)

**Most Likely Cause:**
WordPress sites are calling **external APIs that are timing out**:

1. **Antispam HOST API** (quigs.com)
   - All client sites call quigs.com for spam checks
   - quigs.com is down → all sites wait indefinitely

2. **Site Manager HOST API** (quigs.com?)
   - Update checks may be timing out
   - Plugin update manager waiting for response

3. **WordPress.org API**
   - Core/plugin update checks
   - API may be rate-limiting or timing out

4. **Third-party Services**
   - Jetpack, AIOSEO, WooCommerce, etc.
   - External API calls during initialization

### The Vicious Cycle

```
Site loads → Calls quigs.com API → quigs.com down → Timeout (30s)
     ↓
quigs.com loads → Calls own HOST APIs → Stuck in loop → Timeout
     ↓
All sites stuck waiting → PHP workers saturated → New requests timeout
     ↓
Server load climbs → Performance degrades → More timeouts
```

---

## Emergency Actions Taken

1. ✅ Restarted all PHP-FPM services (7.4, 8.1, 8.2, 8.3)
2. ✅ Restarted Apache and Nginx
3. ✅ Verified MySQL healthy
4. ⚠️ Rolled back quigs.com to PHP 8.2 (no improvement)

---

## Immediate Recovery Steps

### Option 1: Disable External API Calls (RECOMMENDED)

**Break the cycle by preventing WordPress from making external requests:**

```bash
# Add to wp-config.php on ALL sites
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('WP_ACCESSIBLE_HOSTS', 'api.wordpress.org,*.wordpress.org');
```

**Impact:**
- ✅ Sites will load (no more waiting for APIs)
- ⚠️ Plugin updates won't work temporarily
- ⚠️ Antispam won't work temporarily
- ⚠️ External services (Jetpack, etc.) won't work

**Recovery:**
1. Add HTTP block to wp-config on all sites
2. Wait for sites to recover
3. Investigate root cause
4. Remove block once issue identified

### Option 2: Emergency Maintenance Mode

**Create static HTML on all sites:**

```bash
# For each site
echo "<!DOCTYPE html><html><body><h1>Temporarily Unavailable</h1></body></html>" > \
  /home/brandon/web/{site}/public_html/maintenance.html

# Nginx redirect all traffic to maintenance page
```

**Impact:**
- ✅ Users see maintenance message (not timeout)
- ⚠️ All functionality offline
- ✅ Server load drops to normal

### Option 3: Restart Server (LAST RESORT)

**Nuclear option - full server reboot:**

```bash
sudo reboot
```

**Impact:**
- ⚠️ 2-5 minute downtime for ALL services
- ✅ Clears all stuck processes
- ❓ May not fix root cause (cycle may resume)

---

## Long-term Investigation Needed

1. **Identify which external API is timing out**
   - Check WordPress debug logs
   - Monitor network traffic
   - Review plugin initialization hooks

2. **Fix antispam HOST dependency**
   - quigs.com should not depend on itself
   - CLIENT sites should gracefully handle HOST downtime
   - Implement timeout and fallback logic

3. **Review PHP-FPM pool settings**
   - Current: pm.max_children = 8 per site
   - May need to increase or use dynamic scaling
   - Consider global connection limits

4. **Implement health monitoring**
   - Alert when load > 20
   - Alert when multiple sites timing out
   - Auto-restart PHP-FPM on saturation

---

## Business Impact

### Downtime
- **Duration:** 45+ minutes (and counting)
- **Sites Affected:** 30+ production WordPress sites
- **Services Down:** All websites, forms, e-commerce

### Critical Sites
- quigs.com (main company site)
- ainsworthwi.gov (government site)
- fcal-wis.org (association site)
- charliesbikeshop.com (e-commerce)
- [... 26+ more production sites ...]

### Estimated Financial Impact
- E-commerce sites: Lost sales
- Contact forms: Lost leads
- SEO: Potential ranking impact
- Reputation: Customer trust

---

## Recommended Immediate Action

**IMPLEMENT OPTION 1: Block External HTTP Requests**

This will:
1. Break the API timeout cycle
2. Allow sites to load (degraded functionality)
3. Give time to investigate root cause
4. Minimize further damage

**Command to execute:**
```bash
# Script to add HTTP block to all wp-config.php files
for SITE in /home/brandon/web/*/public_html; do
  if [ -f "$SITE/wp-config.php" ]; then
    # Add before require_once ABSPATH line
    sudo sed -i "/require_once.*ABSPATH/i define('WP_HTTP_BLOCK_EXTERNAL', true);\ndefine('WP_ACCESSIBLE_HOSTS', 'api.wordpress.org');\n" "$SITE/wp-config.php"
  fi
done

# Restart PHP-FPM
sudo systemctl restart php8.2-fpm php8.3-fpm
```

---

**STATUS:** 🔴 **EMERGENCY - AWAITING USER DECISION**
**TIME:** 16:25 CST
**PRIORITY:** CRITICAL - IMMEDIATE ACTION REQUIRED
