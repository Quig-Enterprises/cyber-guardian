# Codebase Security Scan Report

**Generated:** 2026-03-08 12:00:11

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Projects Scanned** | 11 |
| **Files Scanned** | 6879 |
| **Total Issues** | 131 |
| **CRITICAL** | 3 |
| **HIGH** | 83 |
| **MEDIUM** | 0 |
| **LOW** | 45 |

---

## Critical Findings

### 3 Critical Issues Require Immediate Attention

#### 1. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/opt/claude-workspace/projects/cxq-woocommerce-product-map/products-xml.php:114`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$attribute_taxonomies = $wpdb->get_results( "SELECT * FROM " . $wpdb->prefix . "woocommerce_attribute_taxonomies order by attribute_name ASC;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 2. Deprecated mysql_query() with variable input

**File:** `/opt/claude-workspace/projects/archive/_shared/database/dbOps.class.php:327`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Deprecated mysql_query() with variable input

**Code:**
```php
mysql_query($query, $link);
```

**Recommendation:**
Use PDO or mysqli with prepared statements

---

#### 3. Hardcoded credential or API key detected

**File:** `/opt/claude-workspace/projects/dev-team-app/frontend/src/hooks/useWebSocket.js:21`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credential or API key detected

**Code:**
```php
console.log('[WS] Connecting with token:', token ? token.substring(0, 20) + '...' : 'NO TOKEN')
```

**Recommendation:**
Move secrets to environment variables (process.env / import.meta.env)

---

## Projects Summary

| Project | Files | Issues | CRITICAL | HIGH | MEDIUM | LOW |
|---------|-------|--------|----------|------|--------|-----|
| eqmon | 106 | 53 | 0 | 53 | 0 | 0 |
| archive | 537 | 39 | 1 | 3 | 0 | 35 |
| groundtruth-studio | 29 | 15 | 0 | 15 | 0 | 0 |
| hestia-automation | 39 | 9 | 0 | 2 | 0 | 7 |
| finance-manager | 5918 | 5 | 0 | 5 | 0 | 0 |
| cxq-woocommerce-product-map | 7 | 4 | 1 | 3 | 0 | 0 |
| cxq-libs | 95 | 2 | 0 | 0 | 0 | 2 |
| ecoeye-alert-relay | 8 | 1 | 0 | 0 | 0 | 1 |
| cyber-guardian | 30 | 1 | 0 | 1 | 0 | 0 |
| project-keystone-dashboard | 60 | 1 | 0 | 1 | 0 | 0 |
| dev-team-app | 50 | 1 | 1 | 0 | 0 | 0 |

## Issues by Category

### XSS JS (79 issues)

**CRITICAL:** 0, **HIGH:** 79

### WEAK CRYPTO (48 issues)

**CRITICAL:** 0, **HIGH:** 3

### SQL INJECTION (2 issues)

**CRITICAL:** 2, **HIGH:** 0

### FILE UPLOAD (1 issues)

**CRITICAL:** 0, **HIGH:** 1

### CREDENTIALS JS (1 issues)

**CRITICAL:** 1, **HIGH:** 0
