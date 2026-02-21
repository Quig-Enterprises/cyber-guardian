# All WordPress Sites Status Report
**Date:** February 20, 2026
**Test Time:** 17:15 CST
**After:** Emergency HTTP blocking implemented

---

## Summary

- ✅ **Working (HTTP 200 fast):** 9 sites
- ⚠️ **Working but slow (>3s):** 7 sites
- ⚠️ **HTTP errors (403, 303):** 4 sites
- ❌ **Timeout/Down:** 11 sites
- **Total tested:** 31 production sites

**Recovery Rate:** 52% fully functional, 74% partially accessible

---

## Working Sites - Fast (9) ✅

1. lakelucernewi.org (2.1s)
2. lionseyesresearch.com (2.0s)
3. midnorthepoxyflooring.com (0.9s)
4. northwoodsdance.com (2.1s)
5. northwoodsmail.com (0.5s)
6. pearsonpickerellions.org (2.8s)
7. pickerel-pearson.com (2.1s)
8. pickerelfirerescue.org (0.8s)
9. places.quigs.com (0.4s)

---

## Working Sites - Slow (7) ⚠️

Performance >3 seconds (acceptable but degraded):

1. ainsworthwi.gov (3.2s)
2. antigoarborists.com (14.1s) - Very slow
3. antispam-test1.dev.quigs.com (4.0s)
4. kennedyfamilyreunion.com (12.9s) - Very slow
5. kettlebowl.org (6.5s)
6. pinegroveresortpickerel.com (12.3s) - Very slow

**Note:** 3 sites extremely slow (12-14s) - may have additional issues

---

## HTTP Errors (4) ⚠️

Sites returning non-200 status codes:

1. **ainsworth.quigs.com** - HTTP 303 (Redirect)
2. **charliesbikeshop.com** - HTTP 403 (Forbidden)
3. **dev.charliesbikeshop.com** - HTTP 403 (Forbidden)
4. **freeleeliving.com** - HTTP 403 (Forbidden)
5. **maplewoodgolfcourse.com** - HTTP 403 (Forbidden)

**Likely cause:** Security plugin (Wordfence, Sucuri) blocking requests, or .htaccess rules

---

## Failed/Timeout Sites (11) ❌

Complete timeouts after 15 seconds:

1. **api.quigs.com**
2. **fcal-wis.org** (was working earlier!)
3. **integralrailroad.com**
4. **patrolschedule.com**
5. **quigbooks.com**
6. **quigs.com** (CRITICAL - main site + HOST)
7. **sandbox.quigs.com**
8. **signage.quigs.com**
9. **smallbeebrandsolutions.com**
10. **tombstonepickerel.com**

**Critical:** quigs.com is the antispam HOST - affects all client sites

---

## Analysis

### Regression: fcal-wis.org

**PROBLEM:** fcal-wis.org was working 15 minutes ago (HTTP 200, 2.0s) but now timing out again.

**This suggests the issue is recurring** - sites are becoming unstable again.

### Pattern Recognition

**Sites timing out share characteristics:**
- Many have WooCommerce (quigbooks.com, charliesbikeshop.com via 403)
- Some have heavy plugins (fcal-wis.org, tombstonepickerel.com)
- quigs.com has HOST+CLIENT plugin combination

### HTTP 403 Pattern

All 403 errors are different sites, suggesting:
- Wordfence/security plugin blocking curl user-agent
- .htaccess IP blocking
- Not actual downtime - sites may be accessible via browser

---

## Server Status

```bash
Current load: ~35 (still high)
PHP processes: 40-50 (many stuck)
MySQL: Healthy
Apache/Nginx: Running
```

**Load is not decreasing as expected** - suggests ongoing issues.

---

## Root Cause Assessment

### Why HTTP Blocking Didn't Fully Fix It

The HTTP blocking should have resolved external API timeouts, but 11 sites still down suggests:

1. **Internal WordPress issues** (not just external APIs)
   - Database queries timing out
   - Plugin initialization loops
   - Theme rendering issues

2. **PHP-FPM pool saturation**
   - Some sites exhausting their 8 workers
   - New requests queued indefinitely
   - Pools not recovering between requests

3. **Cascading dependency issues**
   - quigs.com down → other sites calling it → timeout
   - HTTP blocking may not block all internal calls

4. **Resource exhaustion**
   - Server load still 35 (should be <10)
   - Memory pressure
   - I/O contention

---

## Recommendations

### Immediate Actions Needed

1. **Investigate fcal-wis.org regression**
   ```bash
   # Why did it stop working again?
   tail -f /var/log/apache2/domains/fcal-wis.org.error.log
   ps aux | grep 'php.*fcal-wis'
   ```

2. **Fix HTTP 403 sites**
   ```bash
   # Test with browser user-agent
   curl -A "Mozilla/5.0" https://charliesbikeshop.com
   ```

3. **Restart PHP-FPM again**
   ```bash
   # Clear all stuck processes
   systemctl restart php8.2-fpm php8.3-fpm
   ```

4. **Check server resources**
   ```bash
   # Look for resource exhaustion
   free -h
   df -h
   iostat -x 1 5
   ```

### Nuclear Options

If sites continue to fail:

1. **Disable all plugins via database**
   ```sql
   UPDATE wp_options SET option_value = 'a:0:{}'
   WHERE option_name = 'active_plugins';
   ```
   Run on all databases for timeout sites

2. **Switch to default theme**
   ```bash
   wp theme activate twentytwentyfour
   ```
   For each timeout site

3. **Full server restart**
   ```bash
   sudo reboot
   ```
   Nuclear option - clears everything

---

## Next Steps

**Priority 1: Understand why recovery is failing**

The fact that fcal-wis.org regressed from working to timeout indicates:
- The fix is not stable
- There's a recurring issue
- Sites are in unstable state

**Need to:**
1. Check if HTTP blocking is being overridden
2. Verify no plugins are bypassing the block
3. Check for WordPress cron running despite block
4. Monitor PHP-FPM pool status in real-time

**Priority 2: Fix quigs.com**

As the HOST server, quigs.com being down affects client sites.

**Priority 3: Investigate 403 errors**

May be false positives - sites could be working fine via browser.

---

**Status:** 🟡 **UNSTABLE RECOVERY**
**Working:** 16/31 sites (52%)
**Issue:** Recovery not holding - sites regressing to timeout
**Action:** Need deeper investigation
