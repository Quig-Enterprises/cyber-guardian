# Codebase Security Scan Report

**Generated:** 2026-03-09 18:00:12

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Projects Scanned** | 10 |
| **Files Scanned** | 6825 |
| **Total Issues** | 80 |
| **CRITICAL** | 4 |
| **HIGH** | 28 |
| **MEDIUM** | 3 |
| **LOW** | 45 |

---

## Critical Findings

### 4 Critical Issues Require Immediate Attention

#### 1. Hardcoded credentials detected

**File:** `/opt/claude-workspace/projects/cyber-guardian/dashboard/api/init-mitigation.php:9`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$init_password = 'temp_import_2026';
```

**Recommendation:**
Move credentials to environment variables or wp-config constants

---

#### 2. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

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

#### 3. Deprecated mysql_query() with variable input

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

#### 4. Hardcoded credential or API key detected

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
| archive | 537 | 39 | 1 | 3 | 0 | 35 |
| eqmon | 106 | 18 | 0 | 15 | 3 | 0 |
| hestia-automation | 39 | 9 | 0 | 2 | 0 | 7 |
| groundtruth-studio | 29 | 5 | 0 | 5 | 0 | 0 |
| finance-manager | 5918 | 3 | 0 | 3 | 0 | 0 |
| cxq-libs | 95 | 2 | 0 | 0 | 0 | 2 |
| ecoeye-alert-relay | 7 | 1 | 0 | 0 | 0 | 1 |
| cyber-guardian | 38 | 1 | 1 | 0 | 0 | 0 |
| cxq-woocommerce-product-map | 7 | 1 | 1 | 0 | 0 | 0 |
| dev-team-app | 49 | 1 | 1 | 0 | 0 | 0 |

## Issues by Category

### WEAK CRYPTO (48 issues)

**CRITICAL:** 0, **HIGH:** 3

### XSS JS (27 issues)

**CRITICAL:** 0, **HIGH:** 24

### SQL INJECTION (2 issues)

**CRITICAL:** 2, **HIGH:** 0

### CREDENTIALS (1 issues)

**CRITICAL:** 1, **HIGH:** 0

### FILE UPLOAD (1 issues)

**CRITICAL:** 0, **HIGH:** 1

### CREDENTIALS JS (1 issues)

**CRITICAL:** 1, **HIGH:** 0
