# Codebase Security Scan Report

**Generated:** 2026-03-07 14:00:54

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Projects Scanned** | 56 |
| **Files Scanned** | 23195 |
| **Total Issues** | 974 |
| **CRITICAL** | 391 |
| **HIGH** | 41 |
| **MEDIUM** | 0 |
| **LOW** | 542 |

---

## Critical Findings

### 391 Critical Issues Require Immediate Attention

#### 1. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-email-relay/includes/class-cxq-email-relay.php:471`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$patterns = $wpdb->get_col("SELECT sender_pattern FROM {$table} WHERE is_active = 1");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 2. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-email-relay/includes/admin/class-cxq-email-relay-admin.php:569`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$senders = $wpdb->get_results("SELECT * FROM {$table} ORDER BY sender_pattern ASC");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 3. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-email-relay/includes/admin/class-cxq-email-relay-admin.php:1645`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$patterns = $wpdb->get_col("SELECT sender_pattern FROM {$table} WHERE is_active = 1");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 4. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/uninstall.php:37`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP TABLE IF EXISTS " . $wpdb->prefix . "wcpv_commissions" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 5. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/uninstall.php:38`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP TABLE IF EXISTS " . $wpdb->prefix . "wcpv_per_product_shipping_rules" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 6. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/includes/class-wc-product-vendors-commission.php:177`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$commissions = $wpdb->get_results( "SELECT DISTINCT `id`, `order_id`, `order_item_id`, `vendor_id`, `total_commission_amount` FROM {$this->table_name} WHERE `id` IN ( $commission_ids ) AND `commission_status` = 'unpaid'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 7. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/includes/class-wc-product-vendors-commission.php:229`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$commissions = $wpdb->get_results( "SELECT DISTINCT `id`, `order_id` FROM {$this->table_name} WHERE `commission_status` = 'unpaid'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 8. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/includes/class-wc-product-vendors-commission.php:262`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$commissions = $wpdb->get_results( "SELECT * FROM {$this->table_name} WHERE `commission_status` = 'unpaid'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 9. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/includes/class-wc-product-vendors-install.php:294`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( ! $wpdb->get_var( "SHOW COLUMNS FROM `{$wpdb->prefix}wcpv_commissions` LIKE 'id';" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 10. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/includes/class-wc-product-vendors-install.php:295`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wcpv_commissions DROP PRIMARY KEY, ADD `id` bigint(20) NOT NULL PRIMARY KEY AUTO_INCREMENT;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 11. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/includes/class-wc-product-vendors-install.php:303`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( ! $wpdb->get_var( "SHOW COLUMNS FROM `{$wpdb->prefix}wcpv_per_product_shipping_rules` LIKE 'rule_id';" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 12. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/includes/class-wc-product-vendors-install.php:304`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wcpv_per_product_shipping_rules DROP PRIMARY KEY, ADD `rule_id` bigint(20) NOT NULL PRIMARY KEY AUTO_INCREMENT;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 13. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/includes/admin/updates/wc-product-vendors-update-2.0.0.php:141`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->prefix}woocommerce_order_itemmeta WHERE `meta_key` = '_commission'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 14. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceURLHoover.php:29`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$blogIDs = $wpdb->get_col("SELECT blog_id FROM {$wpdb->blogs}"); //Can't use wp_get_sites or get_sites because they return empty at 10k sites
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 15. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wfLog.php:87`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$table} WHERE `expiration` < UNIX_TIMESTAMP()");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 16. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wfScanEngine.php:3044`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$files = $wpdb->get_col("SELECT path FROM {$table_wfKnownFileList} WHERE path REGEXP '(^|/){$escapedFile}$'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 17. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wfUtils.php:3028`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$url = $wpdb->get_var("SELECT option_value FROM {$wpdb->options} WHERE option_name = 'home' LIMIT 1");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 18. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wfUtils.php:3030`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$url = $wpdb->get_var("SELECT option_value FROM {$wpdb->options} WHERE option_name = 'siteurl' LIMIT 1");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 19. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wfUtils.php:3116`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$url = $wpdb->get_var("SELECT option_value FROM {$wpdb->options} WHERE option_name = 'siteurl' LIMIT 1");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 20. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:501`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$configTable} ADD COLUMN autoload ENUM('no', 'yes') NOT NULL DEFAULT 'yes'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 21. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:502`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("UPDATE {$configTable} SET autoload = 'no' WHERE name = 'wfsd_engine' OR name LIKE 'wordfence_chunked_%'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 22. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:550`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = $wpdb->get_row("SHOW FIELDS FROM {$ptable} where field = 'IP'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 23. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:558`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = $wpdb->get_row("SHOW FIELDS FROM {$ptable} where field = 'IP'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 24. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:691`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$snipCacheTable}` ADD `type` INT  UNSIGNED  NOT NULL  DEFAULT '0'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 25. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:692`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$snipCacheTable}` ADD INDEX (`type`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 26. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:705`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$fileModsTable} ADD COLUMN stoppedOnSignature VARCHAR(255) NOT NULL DEFAULT ''");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 27. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:706`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$fileModsTable} ADD COLUMN stoppedOnPosition INT UNSIGNED NOT NULL DEFAULT '0'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 28. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:718`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$blockedIPLogTable} ADD blockType VARCHAR(50) NOT NULL DEFAULT 'generic'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 29. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:719`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$blockedIPLogTable} DROP PRIMARY KEY");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 30. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:720`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$blockedIPLogTable} ADD PRIMARY KEY (IP, unixday, blockType)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 31. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:741`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$fileModsTable} ADD COLUMN `SHAC` BINARY(32) NOT NULL DEFAULT '' AFTER `newMD5`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 32. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:742`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$fileModsTable} ADD COLUMN `isSafeFile` VARCHAR(1) NOT NULL  DEFAULT '?' AFTER `stoppedOnPosition`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 33. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:755`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$hooverTable} CHANGE `hostKey` `hostKey` VARBINARY(124) NULL DEFAULT NULL");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 34. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:829`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$advancedBlocks = $wpdb->get_results("SELECT * FROM {$advancedBlocksTable}", ARRAY_A);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 35. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:845`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$throttles = $wpdb->get_results("SELECT * FROM {$throttleTable}", ARRAY_A);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 36. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:858`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$lockouts = $wpdb->get_results("SELECT * FROM {$lockoutTable}", ARRAY_A);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 37. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:890`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$issuesTable}` ADD `lastUpdated` INT UNSIGNED NOT NULL AFTER `time`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 38. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:891`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$issuesTable}` ADD INDEX (`lastUpdated`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 39. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:892`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$issuesTable}` ADD INDEX (`status`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 40. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:893`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$issuesTable}` ADD INDEX (`ignoreP`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 41. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:894`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$issuesTable}` ADD INDEX (`ignoreC`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 42. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:895`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("UPDATE `{$issuesTable}` SET `lastUpdated` = `time` WHERE `lastUpdated` = 0");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 43. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:897`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$pendingIssuesTable}` ADD `lastUpdated` INT UNSIGNED NOT NULL AFTER `time`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 44. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:898`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$pendingIssuesTable}` ADD INDEX (`lastUpdated`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 45. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:899`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$pendingIssuesTable}` ADD INDEX (`status`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 46. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:900`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$pendingIssuesTable}` ADD INDEX (`ignoreP`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 47. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:901`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$pendingIssuesTable}` ADD INDEX (`ignoreC`)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 48. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:1103`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM `{$knownFilesTable}`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 49. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:1104`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$knownFilesTable}` ADD COLUMN wordpress_path TEXT NOT NULL");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 50. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:1109`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM `{$fileModsTable}`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 51. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:1110`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$fileModsTable}` ADD COLUMN real_path TEXT NOT NULL AFTER filename");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 52. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:1114`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$fileModsTable} ALTER COLUMN oldMD5 SET DEFAULT ''");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 53. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:4930`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$row = $wpdb->get_row("SELECT ctime, msg FROM {$statusTable} WHERE level < 3 AND ctime > (UNIX_TIMESTAMP() - 3600) ORDER BY ctime DESC LIMIT 1", ARRAY_A);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 54. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:5965`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$table} WHERE `timestamp` < DATE_SUB(NOW(), INTERVAL 1 DAY)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 55. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wordfenceClass.php:5971`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$highestDeletableId = $wpdb->get_var("SELECT id FROM {$table} ORDER BY id DESC LIMIT 1 OFFSET 25");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 56. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wfConfig.php:303`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if (!($rawOptions = $wpdb->get_results("SELECT name, val FROM {$table} WHERE autoload = 'yes'"))) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 57. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wfConfig.php:304`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$rawOptions = $wpdb->get_results("SELECT name, val FROM {$table}");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 58. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/lib/wfConfig.php:628`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$rows = $wpdb->get_results("SELECT name, val, autoload FROM {$table} WHERE name IN ({$keysINClause})", ARRAY_A);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 59. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/utility/multisite.php:35`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->get_results("SELECT * FROM {$wpdb->blogs} WHERE blog_id IN ({$blogIdsQuery}) AND archived = 0 AND spam = 0 AND deleted = 0");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 60. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/utility/multisite.php:38`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->get_results("SELECT * FROM {$wpdb->blogs} WHERE archived = 0 AND spam = 0 AND deleted = 0");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 61. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/model/2fainitializationdata.php:33`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
return "otpauth://totp/" . rawurlencode(preg_replace('~^https?://(?:www\.)?~i', '', home_url()) . ':' . $this->user->user_login) . '?secret=' . $this->get_base32_secret() . '&algorithm=SHA1&digits=6&period=30&issuer=' . rawurlencode(preg_replace('~^https?://(?:www\.)?~i', '', home_url()));
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 62. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/controller/users.php:592`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->get_col("SELECT DISTINCT `user_id` FROM {$table}");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 63. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/controller/permissions.php:162`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->get_col("SELECT blogs.blog_id FROM {$wpdb->site} sites JOIN {$wpdb->blogs} blogs ON blogs.site_id=sites.id AND blogs.path=sites.path");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 64. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/controller/permissions.php:177`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->get_col("SELECT `blog_id` FROM `{$wpdb->blogs}` WHERE `deleted` = 0 ORDER BY blog_id ");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 65. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/controller/permissions.php:280`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$blogs = $blog_ids===null?$wpdb->get_col("SELECT `blog_id` FROM `{$wpdb->blogs}` WHERE `deleted` = 0"):$blog_ids;
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 66. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/controller/permissions.php:306`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$blogs = $blog_ids===null?$wpdb->get_col("SELECT `blog_id` FROM `{$wpdb->blogs}` WHERE `deleted` = 0"):$blog_ids;
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 67. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/modules/login-security/classes/model/settings/db.php:76`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$raw = $wpdb->get_results("SELECT `name`, `value` FROM `{$table}` WHERE `autoload` = 'yes'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 68. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/models/block/wfBlock.php:560`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM `{$blocksTable}` WHERE `expiration` <= UNIX_TIMESTAMP() AND `expiration` != " . self::DURATION_FOREVER);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 69. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/models/block/wfBlock.php:574`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$removing = self::_recordsFromRows($wpdb->get_results("SELECT * FROM `{$blocksTable}` WHERE `expiration` = " . self::DURATION_FOREVER, ARRAY_A));
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 70. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/models/block/wfBlock.php:1117`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$rows = $wpdb->get_results("SELECT * FROM `{$blocksTable}` WHERE `type` IN (" . implode(', ', array(self::TYPE_IP_MANUAL, self::TYPE_IP_AUTOMATIC_TEMPORARY, self::TYPE_IP_AUTOMATIC_PERMANENT, self::TYPE_WFSN_TEMPORARY, self::TYPE_RATE_BLOCK, self::TYPE_RATE_THROTTLE, self::TYPE_LOCKOUT)) . ")", ARRAY_A);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 71. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/models/block/wfBlock.php:1130`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$rows = $wpdb->get_results("SELECT * FROM `{$blocksTable}` WHERE `type` IN (" . implode(', ', array(self::TYPE_COUNTRY)) . ")", ARRAY_A);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 72. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/models/block/wfBlock.php:1188`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$rows = $wpdb->get_results("SELECT * FROM `{$blocksTable}` WHERE `IP` = {$ipHex}", ARRAY_A);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 73. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wordfence/models/block/wfBlock.php:1682`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$data = wfUtils::array_kmap(function($r) { return array($r['id'] => $r); }, $wpdb->get_results("SELECT * FROM `{$blocksTable}` WHERE `id` IN ({$populateInClause})", ARRAY_A));
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 74. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership/includes/migration-phase2.php:100`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$user_ids = $wpdb->get_col("SELECT ID FROM {$wpdb->users}");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 75. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership/includes/migration-phase2.php:194`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = '_org_positions'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 76. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership/includes/migration-phase2.php:195`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = '_primary_position'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 77. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership/includes/migration-phase2.php:196`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = '_credentials'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 78. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership/src/Admin/PlaceClaimsPage.php:478`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$claims = $wpdb->get_results("SELECT * FROM {$table} {$where} ORDER BY claim_date DESC");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 79. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:54`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->comments} WHERE key_name = 'woo_idx_comment_type';" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 80. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:56`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->comments} DROP INDEX woo_idx_comment_type;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 81. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:58`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$date_type_index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->comments} WHERE key_name = 'woo_idx_comment_date_type';" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 82. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:60`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->comments} DROP INDEX woo_idx_comment_date_type;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 83. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:77`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wc_attributes = array_filter( (array) $wpdb->get_col( "SELECT attribute_name FROM {$wpdb->prefix}woocommerce_attribute_taxonomies;" ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 84. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:93`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->posts} WHERE post_type IN ( 'product', 'product_variation', 'shop_coupon', 'shop_order', 'shop_order_refund' );" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 85. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:94`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE meta FROM {$wpdb->postmeta} meta LEFT JOIN {$wpdb->posts} posts ON posts.ID = meta.post_id WHERE posts.ID IS NULL;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 86. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:96`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->comments} WHERE comment_type IN ( 'order_note' );" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 87. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:97`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE meta FROM {$wpdb->commentmeta} meta LEFT JOIN {$wpdb->comments} comments ON comments.comment_ID = meta.comment_id WHERE comments.comment_ID IS NULL;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 88. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:122`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE tr FROM {$wpdb->term_relationships} tr LEFT JOIN {$wpdb->posts} posts ON posts.ID = tr.object_id WHERE posts.ID IS NULL;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 89. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:125`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE t FROM {$wpdb->terms} t LEFT JOIN {$wpdb->term_taxonomy} tt ON t.term_id = tt.term_id WHERE tt.term_id IS NULL;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 90. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/uninstall.php:129`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE tm FROM {$wpdb->termmeta} tm LEFT JOIN {$wpdb->term_taxonomy} tt ON tm.term_id = tt.term_id WHERE tt.term_id IS NULL;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 91. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-term-functions.php:288`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( $wpdb->query( "INSERT INTO {$wpdb->termmeta} ( term_id, meta_key, meta_value ) SELECT woocommerce_term_id, meta_key, meta_value FROM {$wpdb->prefix}woocommerce_termmeta;" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 92. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-term-functions.php:289`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}woocommerce_termmeta" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 93. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:50`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$existing_file_paths = $wpdb->get_results( "SELECT meta_value, meta_id, post_id FROM {$wpdb->postmeta} WHERE meta_key = '_file_path' AND meta_value != '';" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 94. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:503`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$existing_file_paths = $wpdb->get_results( "SELECT meta_value, meta_id FROM {$wpdb->postmeta} WHERE meta_key = '_file_paths' AND meta_value != '';" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 95. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1086`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( $wpdb->query( "INSERT INTO {$wpdb->termmeta} ( term_id, meta_key, meta_value ) SELECT woocommerce_term_id, meta_key, meta_value FROM {$wpdb->prefix}woocommerce_termmeta;" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 96. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1087`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}woocommerce_termmeta" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 97. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1104`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( $wpdb->get_var( "SHOW COLUMNS FROM `{$wpdb->prefix}woocommerce_shipping_zones` LIKE 'zone_enabled';" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 98. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1105`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}woocommerce_shipping_zones CHANGE `zone_type` `zone_type` VARCHAR(40) NOT NULL DEFAULT '';" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 99. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1106`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}woocommerce_shipping_zones CHANGE `zone_enabled` `zone_enabled` INT(1) NOT NULL DEFAULT 1;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 100. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1123`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$old_methods = $wpdb->get_results( "SELECT zone_id, shipping_method_type, shipping_method_order, shipping_method_id FROM {$wpdb->prefix}woocommerce_shipping_zone_shipping_methods;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 101. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1192`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "UPDATE {$wpdb->prefix}woocommerce_shipping_zone_locations SET location_code = REPLACE( location_code, '-', '...' );" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 102. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1258`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->comments} WHERE column_name = 'comment_type' and key_name = 'woo_idx_comment_type'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 103. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1263`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->comments} ADD INDEX woo_idx_comment_type (comment_type)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 104. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1392`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->prefix}woocommerce_downloadable_product_permissions WHERE column_name = 'order_id' and key_name = 'order_id'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 105. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1395`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}woocommerce_downloadable_product_permissions ADD INDEX order_id (order_id)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 106. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1860`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$create_table_sql = $wpdb->get_var( "SHOW CREATE TABLE {$wpdb->prefix}wc_download_log", 1 );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 107. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1866`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_download_log DROP FOREIGN KEY `{$foreign_key_name}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 108. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1926`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$create_table_sql = $wpdb->get_var( "SHOW CREATE TABLE {$wpdb->prefix}wc_download_log", 1 );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 109. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1930`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_download_log DROP FOREIGN KEY fk_wc_download_log_permission_id" ); // phpcs:ignore WordPress.WP.PreparedSQL.NotPrepared
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 110. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1973`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "UPDATE {$wpdb->termmeta} SET meta_key = 'order' WHERE meta_key LIKE 'order_pa_%';" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 111. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1984`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->prefix}woocommerce_downloadable_product_permissions WHERE key_name = 'user_order_remaining_expires'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 112. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:1987`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}woocommerce_downloadable_product_permissions ADD INDEX user_order_remaining_expires (user_id,order_id,downloads_remaining,access_expires)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 113. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:2112`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_product_meta_lookup MODIFY COLUMN `min_price` decimal(19,4) NULL default NULL" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 114. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:2113`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_product_meta_lookup MODIFY COLUMN `max_price` decimal(19,4) NULL default NULL" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 115. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:2459`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$create_table_sql = $wpdb->get_var( "SHOW CREATE TABLE {$wpdb->prefix}wc_download_log", 1 );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 116. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:2464`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_download_log DROP FOREIGN KEY `{$foreign_key_name}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 117. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:3121`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$date_type_index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->comments} WHERE key_name = 'woo_idx_comment_date_type'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 118. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-update-functions.php:3125`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->comments} ADD INDEX woo_idx_comment_date_type (comment_date_gmt, comment_type, comment_approved, comment_post_ID)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 119. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-ajax.php:2140`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$menu_orders = wp_list_pluck( $wpdb->get_results( "SELECT ID, menu_order FROM {$wpdb->posts} WHERE post_type = 'product' ORDER BY menu_order ASC, post_title ASC" ), 'menu_order', 'ID' );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 120. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-ajax.php:3375`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( $wpdb->delete( "{$wpdb->prefix}woocommerce_shipping_zone_methods", array( 'instance_id' => $instance_id ) ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 121. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-ajax.php:3409`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->update( "{$wpdb->prefix}woocommerce_shipping_zone_methods", array( 'method_order' => absint( $method_data['method_order'] ) ), array( 'instance_id' => absint( $instance_id ) ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 122. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-ajax.php:3420`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( $wpdb->update( "{$wpdb->prefix}woocommerce_shipping_zone_methods", array( 'is_enabled' => $is_enabled ), array( 'instance_id' => absint( $instance_id ) ) ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 123. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:1670`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( ! $wpdb->get_var( "SHOW COLUMNS FROM `{$wpdb->prefix}woocommerce_downloadable_product_permissions` LIKE 'permission_id';" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 124. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:1671`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}woocommerce_downloadable_product_permissions DROP PRIMARY KEY, ADD `permission_id` bigint(20) unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 125. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:1677`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_order_product_lookup DROP PRIMARY KEY, ADD PRIMARY KEY (order_item_id, order_id)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 126. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:1690`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( ! $wpdb->get_var( "SHOW KEYS FROM {$wpdb->prefix}woocommerce_sessions WHERE Key_name = 'PRIMARY' AND Column_name = 'session_id'" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 127. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:1699`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$comment_type_index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->comments} WHERE column_name = 'comment_type' and key_name = 'woo_idx_comment_type'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 128. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:1704`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->comments} ADD INDEX woo_idx_comment_type (comment_type)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 129. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:1707`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$date_type_index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->comments} WHERE key_name = 'woo_idx_comment_date_type'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 130. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:1711`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->comments} ADD INDEX woo_idx_comment_date_type (comment_date_gmt, comment_type, comment_approved, comment_post_ID)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 131. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-install.php:2180`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 132. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-tax.php:362`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$postcode_ranges = $wpdb->get_results( "SELECT tax_rate_id, location_code FROM {$wpdb->prefix}woocommerce_tax_rate_locations WHERE location_type = 'postcode' AND location_code LIKE '%...%';" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 133. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-tax.php:945`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE locations FROM {$wpdb->prefix}woocommerce_tax_rate_locations locations LEFT JOIN {$wpdb->prefix}woocommerce_tax_rates rates ON rates.tax_rate_id = locations.tax_rate_id WHERE rates.tax_rate_id IS NULL;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 134. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-tax.php:1215`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "INSERT INTO {$wpdb->prefix}woocommerce_tax_rate_locations ( location_code, tax_rate_id, location_type ) VALUES $sql;" ); // @codingStandardsIgnoreLine.
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 135. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/class-wc-tax.php:1235`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$locations = $wpdb->get_results( "SELECT * FROM `{$wpdb->prefix}woocommerce_tax_rate_locations`" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 136. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/wc-attribute-functions.php:65`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$raw_attribute_taxonomies = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}woocommerce_attribute_taxonomies WHERE attribute_name != '' ORDER BY attribute_name ASC;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 137. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/data-stores/class-wc-shipping-zone-data-store.php:321`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$postcode_locations = $wpdb->get_results( "SELECT zone_id, location_code FROM {$wpdb->prefix}woocommerce_shipping_zone_locations WHERE location_type = 'postcode';" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 138. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/data-stores/class-wc-shipping-zone-data-store.php:360`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->get_results( "SELECT zone_id, zone_name, zone_order FROM {$wpdb->prefix}woocommerce_shipping_zones order by zone_order ASC, zone_id ASC;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 139. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/react-admin/wc-admin-update-functions.php:25`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$index = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->prefix}wc_order_stats WHERE key_name = 'status'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 140. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/react-admin/wc-admin-update-functions.php:34`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP INDEX `status` ON {$wpdb->prefix}wc_order_stats" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 141. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/react-admin/wc-admin-update-functions.php:49`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_order_stats DROP COLUMN `total_sales`" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 142. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/react-admin/wc-admin-update-functions.php:51`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_order_stats CHANGE COLUMN `gross_total` `total_sales` double DEFAULT 0 NOT NULL" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 143. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/react-admin/wc-admin-update-functions.php:75`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE actions FROM {$wpdb->prefix}wc_admin_note_actions actions INNER JOIN {$wpdb->prefix}wc_admin_notes notes USING (note_id) WHERE actions.name = 'tracking-dismiss' AND notes.name = 'wc-admin-usage-tracking-opt-in'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 144. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/react-admin/wc-admin-update-functions.php:277`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_admin_note_actions DROP COLUMN `is_primary`" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 145. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/react-admin/wc-admin-update-functions.php:292`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$index_exists = $wpdb->get_row( "SHOW INDEX FROM {$wpdb->prefix}wc_order_stats WHERE key_name = 'idx_date_paid_status_parent'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 146. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/react-admin/wc-admin-update-functions.php:295`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_order_stats ADD INDEX idx_date_paid_status_parent (date_paid, status, parent_id)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 147. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/log-handlers/class-wc-log-handler-db.php:94`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return false !== $wpdb->insert( "{$wpdb->prefix}woocommerce_log", $insert, $format );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 148. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/log-handlers/class-wc-log-handler-db.php:105`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}woocommerce_log" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 149. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/rest-api/Controllers/Version2/class-wc-rest-shipping-zone-methods-v2-controller.php:329`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->update( "{$wpdb->prefix}woocommerce_shipping_zone_methods", array( 'method_order' => absint( $request['order'] ) ), array( 'instance_id' => absint( $instance_id ) ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 150. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/rest-api/Controllers/Version2/class-wc-rest-shipping-zone-methods-v2-controller.php:335`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( $wpdb->update( "{$wpdb->prefix}woocommerce_shipping_zone_methods", array( 'is_enabled' => $request['enabled'] ), array( 'instance_id' => absint( $instance_id ) ) ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 151. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/rest-api/Controllers/Version2/class-wc-rest-system-status-tools-v2-controller.php:550`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "TRUNCATE {$wpdb->prefix}woocommerce_sessions" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 152. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/rest-api/Controllers/Version2/class-wc-rest-system-status-tools-v2-controller.php:552`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = absint( $wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key='_woocommerce_persistent_cart_" . get_current_blog_id() . "';" ) ); // WPCS: unprepared SQL ok.
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 153. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/rest-api/Controllers/Version2/class-wc-rest-system-status-tools-v2-controller.php:564`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->prefix}woocommerce_tax_rates;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 154. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/rest-api/Controllers/Version2/class-wc-rest-system-status-tools-v2-controller.php:565`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->prefix}woocommerce_tax_rate_locations;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 155. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/rest-api/Controllers/Version1/class-wc-rest-webhooks-v1-controller.php:522`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$data->post_password = 'webhook_' . wp_generate_password();
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 156. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/admin/reports/class-wc-report-downloads.php:333`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$this->items     = $wpdb->get_results( "SELECT * {$query_from} {$query_order}" ); // WPCS: cache ok, db call ok, unprepared SQL ok.
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 157. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/includes/admin/meta-boxes/views/html-order-items.php:485`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$rates = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}woocommerce_tax_rates ORDER BY tax_rate_name LIMIT 100" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 158. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/packages/action-scheduler/classes/data-stores/ActionScheduler_DBStore.php:1169`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$row_updates      = $wpdb->query( "UPDATE {$wpdb->actionscheduler_actions} SET claim_id = 0 WHERE action_id IN ({$action_id_string})" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 159. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Blocks/QueryFilters.php:311`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$product_tax_classes = array_filter( $wpdb->get_col( "SELECT DISTINCT tax_class FROM {$wpdb->wc_product_meta_lookup};" ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 160. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/CostOfGoodsSold/CostOfGoodsSoldController.php:112`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_product_meta_lookup ADD COLUMN cogs_total_value DECIMAL(19,4)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 161. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/CostOfGoodsSold/CostOfGoodsSoldController.php:131`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wc_product_meta_lookup DROP COLUMN cogs_total_value" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 162. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/ProductAttributesLookup/DataRegenerator.php:145`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "TRUNCATE TABLE {$this->lookup_table_name}" ); // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 163. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/ProductAttributesLookup/LookupDataStore.php:709`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return ( (int) $wpdb->get_var( "SELECT EXISTS (SELECT 1 FROM {$this->lookup_table_name})" ) ) !== 0;
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 164. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/ProductFilters/QueryClauses.php:479`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$product_tax_classes = $wpdb->get_col( "SELECT DISTINCT tax_class FROM {$wpdb->wc_product_meta_lookup};" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 165. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/Fulfillments/FulfillmentsController.php:74`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wc_order_fulfillments" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 166. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/Fulfillments/FulfillmentsController.php:75`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wc_order_fulfillment_meta" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 167. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/Utilities/WebhookUtil.php:101`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( $wpdb->get_var( "SELECT ID FROM {$wpdb->posts} WHERE post_author IN( " . implode( ',', $userids ) . ' ) LIMIT 1' ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 168. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/Utilities/WebhookUtil.php:103`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
} elseif ( $wpdb->get_var( "SELECT link_id FROM {$wpdb->links} WHERE link_owner IN( " . implode( ',', $userids ) . ' ) LIMIT 1' ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 169. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/Utilities/DatabaseUtil.php:78`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->query( "DROP TABLE IF EXISTS `{$table_name}`" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 170. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/DataStores/Orders/DataSynchronizer.php:724`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return array_map( 'intval', $wpdb->get_col( $sql . " LIMIT $limit" ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 171. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/DataStores/Orders/DataSynchronizer.php:879`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->prefix}wc_orders_meta WHERE id IN {$order_id_rows_as_sql_list}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 172. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/ProductDownloads/ApprovedDirectories/Register.php:448`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( ! $wpdb->query( "DELETE FROM {$this->get_table()}" ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 173. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/ProductDownloads/ApprovedDirectories/Register.php:501`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( ! $wpdb->query( "UPDATE {$this->get_table()} SET enabled = 1" ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 174. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Internal/ProductDownloads/ApprovedDirectories/Register.php:518`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
if ( ! $wpdb->query( "UPDATE {$this->get_table()} SET enabled = 0" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 175. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Blocks/BlockTypes/AbstractProductGrid.php:416`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$product_variations      = $wpdb->get_results( "SELECT ID as variation_id, post_parent as product_id from {$wpdb->posts} WHERE post_parent IN ( " . implode( ',', $prime_product_ids ) . ' )', ARRAY_A );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 176. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Blocks/BlockTypes/ProductCollection/QueryBuilder.php:875`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$product_tax_classes = $wpdb->get_col( "SELECT DISTINCT tax_class FROM {$wpdb->wc_product_meta_lookup};" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 177. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Admin/Features/Blueprint/Exporters/ExportWCSettingsShipping.php:132`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}woocommerce_shipping_zones", ARRAY_A )
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 178. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Admin/Features/Blueprint/Exporters/ExportWCSettingsShipping.php:146`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}woocommerce_shipping_zone_locations", ARRAY_A )
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 179. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Admin/Features/Blueprint/Exporters/ExportWCSettingsShipping.php:158`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$methods        = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}woocommerce_shipping_zone_methods", ARRAY_A );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 180. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/Admin/Features/OnboardingTasks/Tasks/Tax.php:147`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$rate_exists            = (bool) $wpdb->get_var( "SELECT 1 FROM {$wpdb->prefix}woocommerce_tax_rates limit 1" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 181. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/woocommerce/src/StoreApi/Utilities/ProductQuery.php:453`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$product_tax_classes = $wpdb->get_col( "SELECT DISTINCT tax_class FROM {$wpdb->wc_product_meta_lookup};" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 182. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-seo-pack-pro/app/Common/Core/Core.php:147`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->posts} WHERE post_type = 'aioseo-location'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 183. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-seo-pack-pro/app/Common/Core/Core.php:148`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->term_taxonomy} WHERE taxonomy = 'aioseo-location-category'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 184. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-seo-pack-pro/app/Common/Core/Core.php:151`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'aioseo\_%'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 185. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-seo-pack-pro/app/Common/Core/Core.php:154`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_aioseo\_%'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 186. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-seo-pack-pro/app/Common/Core/Core.php:155`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'aioseo\_%'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 187. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-seo-pack-pro/app/Common/Core/Core.php:158`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->prefix}actionscheduler_actions WHERE hook LIKE 'aioseo\_%'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 188. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-seo-pack-pro/app/Common/Core/Core.php:159`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->prefix}actionscheduler_groups WHERE slug = 'aioseo'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 189. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet.php:755`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "OPTIMIZE TABLE {$wpdb->comments}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 190. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet.php:788`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "OPTIMIZE TABLE {$wpdb->commentmeta}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 191. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet.php:828`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "OPTIMIZE TABLE {$wpdb->commentmeta}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 192. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet.php:1289`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$comment_errors = $wpdb->get_col( "SELECT comment_id FROM {$wpdb->commentmeta} WHERE meta_key = 'akismet_error'	LIMIT 100" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 193. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/akismet/views/notice.php:210`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$at_least_one_comment_in_moderation = ! ! $wpdb->get_var( "SELECT comment_ID FROM {$wpdb->comments} WHERE comment_approved = '0' LIMIT 1" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 194. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-updater-host/cxq-updater-host.php:132`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}quigs_plugin_library");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 195. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-google-hours/cxq-google-hours.php:131`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_cxq_google_hours_%'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 196. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-google-hours/cxq-google-hours.php:132`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_cxq_google_hours_%'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 197. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Events/Custom_Tables/V1/Schema_Builder/Schema_Builder.php:247`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->get_results( "SELECT 1 FROM {$wpdb->posts} LIMIT 1" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 198. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Events/Custom_Tables/V1/Schema_Builder/Abstract_Custom_Table.php:46`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = $wpdb->query( "TRUNCATE {$this_table}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 199. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Events/Custom_Tables/V1/Schema_Builder/Abstract_Custom_Table.php:236`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = $wpdb->query( "DROP TABLE `{$this_table}`" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 200. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Events/Custom_Tables/V1/Models/Builder.php:881`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$results = $wpdb->get_results( $semi_prepared . " OFFSET {$offset}", ARRAY_A );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 201. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Events/Custom_Tables/V1/Tables/Events.php:93`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$updated = $wpdb->query( "ALTER TABLE `{$table_name}`ADD UNIQUE( `post_id` )" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 202. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Events/Custom_Tables/V1/Tables/Occurrences.php:123`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$updated = $wpdb->query( "ALTER TABLE {$this_table} DROP FOREIGN KEY {$foreign_key_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 203. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Events/Custom_Tables/V1/Tables/Occurrences.php:134`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$updated = $wpdb->query( "ALTER TABLE `{$this_table}`ADD UNIQUE( `hash` )" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 204. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Tribe/Aggregator/Cron.php:747`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$post_id            = $wpdb->get_var( "SELECT ID FROM {$wpdb->posts} ORDER BY ID DESC LIMIT 1" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 205. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Tribe/Importer/File_Uploader.php:34`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
$moved = move_uploaded_file( $this->tmp_name, self::get_file_path() );
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 206. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/the-events-calendar/src/Tribe/Google/Maps_API_Key.php:23`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
public static $default_api_key = 'AIzaSyDNsicAsP6-VuGtAb1O9riI3oc_NOb7IOU';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 207. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/motopress-hotel-booking/includes/upgrader.php:594`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE `option_name` = 'mphb_ical_sync_rooms_queue_processed_data'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 208. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/motopress-hotel-booking/includes/upgrader.php:896`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wp_mphb_sync_logs} DROP COLUMN log_context" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 209. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/motopress-hotel-booking/includes/upgrader.php:897`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wp_mphb_sync_logs} MODIFY COLUMN log_message VARCHAR(150)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 210. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/motopress-hotel-booking/includes/repositories/sync-urls-repository.php:55`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$roomIds = $wpdb->get_col( "SELECT DISTINCT room_id FROM {$this->tableName}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 211. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:97`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'wp\_mail\_smtp%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 212. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:100`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 213. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:103`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 214. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:104`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_site\_transient\_wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 215. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:105`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 216. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:106`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_site\_transient\_timeout\_wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 217. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:190`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'wp\_mail\_smtp%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 218. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:193`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 219. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:196`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 220. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:197`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_site\_transient\_wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 221. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:198`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 222. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/uninstall.php:199`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_site\_transient\_timeout\_wp\_mail\_smtp\_%'" ); // phpcs:ignore WordPress.DB
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 223. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/vendor_prefixed/guzzlehttp/psr7/src/UploadedFile.php:127`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
$this->moved = \PHP_SAPI === 'cli' ? \rename($this->file, $targetPath) : \move_uploaded_file($this->file, $targetPath);
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 224. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/vendor_prefixed/psr/http-message/src/UploadedFileInterface.php:35`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
* Use this method as an alternative to move_uploaded_file(). This method is
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 225. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/vendor_prefixed/psr/http-message/src/UploadedFileInterface.php:38`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
* appropriate method (move_uploaded_file(), rename(), or a stream
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 226. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/vendor_prefixed/psr/http-message/src/UploadedFileInterface.php:51`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
* files via moveTo(), is_uploaded_file() and move_uploaded_file() SHOULD be
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 227. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityformsuserregistration/includes/signups.php:15`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$column_exists = $wpdb->query( "SHOW COLUMNS FROM {$wpdb->signups} LIKE 'signup_id'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 228. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-wp-migration-unlimited-extension/uninstall.php:50`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM `{$wpdb->options}` WHERE `option_name` LIKE 'ai1wmue\_%'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 229. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-cloudflare-manager/cxq-cloudflare-manager.php:24`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//protected $zone_api_token = '-xHZ2Ut7wyszICtT_MMJT9out0uHSltENvyi85Ic';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 230. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-cloudflare-manager/cxq-cloudflare-manager.php:25`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
protected $api_key = '3b55771ba3f2a783a2baaa0c11f512b29c7d2'; //
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 231. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms-lite/includes/providers/class-constant-contact.php:56`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
public $api_key = 'c58xq3r27udz59h9rrq7qnvf';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 232. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms-lite/src/Tasks/Actions/Migration175Task.php:153`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$this->entry_meta_handler->table_name} MODIFY type VARCHAR(255)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 233. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms/includes/providers/class-constant-contact.php:48`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
public $api_key = 'c58xq3r27udz59h9rrq7qnvf';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 234. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms/pro/includes/fields/class-file-upload.php:2118`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
if ( false === move_uploaded_file( $path_from, $path_to ) ) {
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 235. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms/src/Tasks/Actions/Migration175Task.php:153`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$this->entry_meta_handler->table_name} MODIFY type VARCHAR(255)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 236. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms/src/Pro/Migrations/Upgrade133.php:31`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$column = $wpdb->get_col( "SHOW COLUMNS FROM {$wpdb->prefix}wpforms_entries LIKE 'user_uuid'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 237. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms/src/Pro/Migrations/Upgrade133.php:38`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wpforms_entries ADD user_uuid VARCHAR(36)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 238. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms/src/Pro/Migrations/Upgrade143.php:138`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$upgraded = count( $wpdb->get_results( "SELECT DISTINCT entry_id FROM {$fields_table}" ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 239. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms/src/Pro/Migrations/Upgrade189.php:31`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$wpdb->prefix}wpforms_entry_fields MODIFY COLUMN field_id VARCHAR(16);" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 240. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/wpforms/src/Pro/Forms/Fields/FileUpload/Chunk.php:386`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
return @move_uploaded_file( $path_from, $path_to );
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 241. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/google-analytics-for-wordpress/includes/database/class-db-base.php:384`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return $wpdb->query( "TRUNCATE TABLE {$table_name}" ) !== false;
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 242. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/google-analytics-for-wordpress/includes/database/class-db-base.php:398`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = $wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 243. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/google-analytics-for-wordpress/includes/database/tables/class-cache-table.php:228`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "OPTIMIZE TABLE {$table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 244. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/modules/widget-visibility/widget-conditions.php:437`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$pages = $wpdb->get_results( "SELECT {$wpdb->posts}.ID, {$wpdb->posts}.post_parent, {$wpdb->posts}.post_title, {$wpdb->posts}.post_status FROM {$wpdb->posts} WHERE {$wpdb->posts}.post_type = 'page' AND {$wpdb->posts}.post_status = 'publish' ORDER BY {$wpdb->posts}.post_title ASC" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 245. Deprecated mysql_query() with variable input

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/_inc/lib/class.jetpack-search-performance-logger.php:75`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Deprecated mysql_query() with variable input

**Code:**
```php
public function log_mysql_query( $found_posts, $query ) {
```

**Recommendation:**
Use PDO or mysqli with prepared statements

---

#### 246. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-forms/src/contact-form/class-contact-form-plugin.php:130`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$feedback_ids = $wpdb->get_col( "SELECT p.ID FROM {$wpdb->posts} as p INNER JOIN {$wpdb->postmeta} as m on m.post_id = p.ID WHERE p.post_type = 'feedback' AND m.meta_key = '_feedback_akismet_values' AND DATE_SUB(NOW(), INTERVAL 15 DAY) > p.post_date_gmt LIMIT 10000" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 247. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-waf/src/class-brute-force-protection.php:603`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
public function check_preauth( $user = 'Not Used By Protect', $username = 'Not Used By Protect', $password = 'Not Used By Protect' ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 248. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-sync/src/modules/class-users.php:805`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$user_ids = $wpdb->get_col( "SELECT user_id FROM $wpdb->usermeta WHERE meta_key = '{$wpdb->prefix}user_level' AND meta_value > 0 LIMIT " . ( self::MAX_INITIAL_SYNC_USERS + 1 ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 249. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-sync/src/modules/class-full-sync.php:351`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$results = $wpdb->get_results( "SELECT MAX({$id}) as max, MIN({$id}) as min, COUNT({$id}) as count FROM {$table} WHERE {$where_sql}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 250. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-sync/src/modules/class-full-sync-immediately.php:317`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$results = $wpdb->get_results( "SELECT MAX({$id}) as max, MIN({$id}) as min, COUNT({$id}) as count FROM {$table} WHERE {$where_sql}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 251. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-sync/src/modules/class-module.php:317`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
while ( $ids = $wpdb->get_col( "SELECT {$id_field} FROM {$table_name} WHERE {$where_sql} AND {$id_field} < {$previous_interval_end} ORDER BY {$id_field} DESC LIMIT {$items_per_page}" ) ) {
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 252. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-sync/src/replicastore/class-table-checksum.php:479`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = $wpdb->get_results( "SHOW COLUMNS FROM {$this->table}", ARRAY_A );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 253. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-sync/src/sync-queue/class-queue-storage-table.php:190`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
return (bool) $wpdb->query( "DROP TABLE {$this->table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 254. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-sync/src/sync-queue/class-queue-storage-table.php:687`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM {$custom_table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 255. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/cxq-facebot.php:322`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$locations = $wpdb->get_results("SELECT * FROM `{$this->table_names['locations']}` order by region, city");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 256. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/cxq-facebot.php:1278`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
//$facebook_ids = $wpdb->get_results("SELECT `facebook_id` FROM {$this->table_names['archive']};");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 257. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/show_main_page.php:152`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$locations = $wpdb->get_results("SELECT * FROM `{$this->table_names['locations']}` order by region, city");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 258. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/CxQ_FaceBot_Conditioner.php:86`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$this->_matches[$id]['facebot'] = $wpdb->get_results("SELECT * FROM {$this->table_name} WHERE `{$record_identifier_key}`={$place[$record_identifier_key]}");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 259. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/class-rest-api.php:2063`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
var token = '{$token}';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 260. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:623`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD COLUMN domain VARCHAR(255) AFTER source_url");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 261. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:624`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD INDEX idx_domain (domain)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 262. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:648`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD COLUMN phone_normalized VARCHAR(20) AFTER phone");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 263. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:649`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD INDEX idx_phone_normalized (phone_normalized)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 264. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:675`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD COLUMN parent_source_id BIGINT(20) UNSIGNED AFTER detected_category");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 265. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:676`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD INDEX idx_parent_source_id (parent_source_id)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 266. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:688`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD COLUMN quality_score TINYINT UNSIGNED DEFAULT NULL AFTER status");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 267. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:689`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD INDEX idx_quality_score (quality_score)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 268. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:701`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$sources_table} ADD COLUMN requires_js TINYINT(1) DEFAULT 0 AFTER quality_score");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 269. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:729`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN referrer_url VARCHAR(2048) DEFAULT NULL AFTER discovered_from");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 270. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:741`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN api_token_id BIGINT(20) UNSIGNED DEFAULT NULL AFTER referrer_url");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 271. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:742`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD INDEX idx_api_token_id (api_token_id)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 272. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:754`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN submission_context JSON DEFAULT NULL AFTER api_token_id");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 273. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:766`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN redirect_to VARCHAR(2048) DEFAULT NULL AFTER status");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 274. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:767`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN redirect_chain JSON DEFAULT NULL AFTER redirect_to");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 275. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:768`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN canonical_url_hash CHAR(64) DEFAULT NULL AFTER redirect_chain");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 276. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:769`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD INDEX idx_canonical_url_hash (canonical_url_hash)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 277. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:793`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN use_browser TINYINT(1) DEFAULT 0 AFTER priority");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 278. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:794`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD INDEX idx_use_browser (use_browser)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 279. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:806`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN browser_attempts TINYINT UNSIGNED DEFAULT 0 AFTER use_browser");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 280. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:818`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN last_http_status SMALLINT UNSIGNED DEFAULT NULL AFTER last_error");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 281. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:830`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$queue_table} ADD COLUMN protection_type VARCHAR(50) DEFAULT NULL AFTER last_http_status");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 282. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:852`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$links_table} ADD COLUMN entity_type VARCHAR(20) DEFAULT 'place' AFTER place_id");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 283. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:853`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE {$links_table} ADD INDEX idx_entity_type (entity_type, place_id)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 284. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/includes/database/class-source-tables.php:856`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("UPDATE {$links_table} SET entity_type = 'place' WHERE entity_type IS NULL");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 285. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-facebot/src/Repositories/DomainBlacklistRepository.php:430`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("TRUNCATE TABLE {$table}");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 286. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/functions.php:144`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$allRevisions = $wpdb->get_results("SELECT post_parent FROM {$wpdb->posts} WHERE post_type = 'revision' AND post_parent != 0 GROUP BY post_parent HAVING COUNT(ID) > {$num_rev}");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 287. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/functions.php:151`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$toKeep = $wpdb->get_results("SELECT ID FROM {$wpdb->posts} WHERE post_type = 'revision' AND post_parent = '{$revision->post_parent}' ORDER BY post_date DESC LIMIT ".$num_rev);
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 288. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/functions.php:163`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->posts} WHERE post_type = 'revision' AND post_parent = '{$revision->post_parent}' AND ID NOT IN ({$keepQuery})");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 289. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/functions.php:243`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->comments} WHERE comment_ID IN ($commentIdsList)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 290. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/functions.php:244`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->commentmeta} WHERE comment_id IN ($commentIdsList)");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 291. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MMB/Stats.php:483`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$network_blogs = (array)$wpdb->get_results("select `blog_id`, `site_id` from `{$wpdb->blogs}`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 292. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MMB/Comment.php:46`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$query_comments = $wpdb->get_results("SELECT c.comment_ID, c.comment_post_ID, c.comment_author, c.comment_author_email, c.comment_author_url, c.comment_author_IP, c.comment_date, c.comment_content, c.comment_approved, c.comment_parent, p.post_title, p.post_type, p.guid FROM ".$sql_query." ORDER BY c.comment_date DESC LIMIT 500");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 293. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MMB/Core.php:241`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$network_blogs = $wpdb->get_results("select `blog_id`, `site_id` from `{$wpdb->blogs}`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 294. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MMB/Core.php:293`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$network_blogs = $wpdb->get_col("select `blog_id` from `{$wpdb->blogs}`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 295. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MMB/Core.php:406`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$networkBlogs = $wpdb->get_results("select `blog_id` from `{$wpdb->blogs}`");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 296. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MWP/Migration/Migration.php:47`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$lockRow          = $wpdb->get_row("SELECT option_value FROM {$wpdb->prefix}options WHERE option_name = '$lockName'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 297. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MWP/Migration/Migration.php:59`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$locked = $wpdb->query("INSERT INTO {$wpdb->prefix}options SET option_name = '$lockName', option_value = '$currentTimestamp'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 298. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MWP/Migration/Migration.php:67`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$released = $wpdb->query("DELETE FROM {$wpdb->prefix}options WHERE option_name = '$lockName'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 299. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MWP/Migration/Migration.php:77`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$version        = (int) $wpdb->get_var("SELECT option_value FROM {$wpdb->prefix}options WHERE option_name = 'worker_migration_version'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 300. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MWP/Migration/Migration.php:91`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("INSERT INTO {$wpdb->prefix}options SET option_name = 'worker_migration_version', option_value = '$migrationVersion' ON DUPLICATE KEY UPDATE option_value = '$migrationVersion'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 301. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MWP/Action/IncrementalBackup/Stats.php:43`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$latestPost                        = $wpdb->get_row("SELECT * FROM {$wpdb->posts} WHERE post_type='post' AND post_status='publish' ORDER BY ID DESC LIMIT 1");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 302. Deprecated mysql_query() with variable input

**File:** `/var/www/html/wordpress/wp-content/plugins/worker/src/MWP/IncrementalBackup/Database/MysqlConnection.php:63`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Deprecated mysql_query() with variable input

**Code:**
```php
$result = mysql_query($query, $this->connection);
```

**Recommendation:**
Use PDO or mysqli with prepared statements

---

#### 303. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/mphb-request-payment/classes/Plugin.php:245`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("UPDATE {$wpdb->options} SET autoload = 'yes' WHERE option_name IN ('mphbrp_configured', 'mphbrp_license_key')");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 304. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/mphb-request-payment/classes/Plugin.php:278`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("UPDATE {$wpdb->options} SET autoload = 'no' WHERE option_name LIKE 'mphbrp_%'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 305. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-event-calendar/cxq-event-calendar.php:1485`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'cxq_event_calendar_%'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 306. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-event-calendar/cxq-event-calendar.php:1486`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'external_event_%'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 307. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-spec-auditor/cxq-auditor.php:100`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
// $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}cxq_audit_requirement_check_items");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 308. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership.backup-20260115/check-admin-status.php:89`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$all_org_options = $wpdb->get_results("SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE 'cxq_mm_%' ORDER BY option_name");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 309. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership.backup-20260115/includes/migration-phase2.php:100`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$user_ids = $wpdb->get_col("SELECT ID FROM {$wpdb->users}");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 310. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership.backup-20260115/includes/migration-phase2.php:194`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = '_org_positions'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 311. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership.backup-20260115/includes/migration-phase2.php:195`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = '_primary_position'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 312. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-membership.backup-20260115/includes/migration-phase2.php:196`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = '_credentials'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 313. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/x_aurora.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = '306bfb022724a25c7d795719358609b1';   //bquig
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 314. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/x_aurora.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//$api_key = 'e8d268dbf5ed7bfa6d01ec9377e1d415';  //lost768
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 315. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/weather-new.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = '306bfb022724a25c7d795719358609b1';   //bquig
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 316. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/weather-new.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//$api_key = 'e8d268dbf5ed7bfa6d01ec9377e1d415';  //lost768
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 317. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/weather.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = '306bfb022724a25c7d795719358609b1';   //bquig
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 318. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/weather.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//$api_key = 'e8d268dbf5ed7bfa6d01ec9377e1d415';  //lost768
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 319. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/sports.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = 'd3be6efcb12a449c497d671557bbeb1e'; // limit hit for May 2022
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 320. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/sports.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = 'f837a07ab0344f6ec917fafdb0276ffa';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 321. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/styles/weather-new.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = '306bfb022724a25c7d795719358609b1';   //bquig
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 322. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/styles/weather-new.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//$api_key = 'e8d268dbf5ed7bfa6d01ec9377e1d415';  //lost768
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 323. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/templates/weather-new.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = '306bfb022724a25c7d795719358609b1';   //bquig
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 324. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/templates/weather-new.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//$api_key = 'e8d268dbf5ed7bfa6d01ec9377e1d415';  //lost768
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 325. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/templates/Xweather-new.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = '306bfb022724a25c7d795719358609b1';   //bquig
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 326. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/templates/Xweather-new.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//$api_key = 'e8d268dbf5ed7bfa6d01ec9377e1d415';  //lost768
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 327. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/templates/weather.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = '306bfb022724a25c7d795719358609b1';   //bquig
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 328. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/templates/weather.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//$api_key = 'e8d268dbf5ed7bfa6d01ec9377e1d415';  //lost768
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 329. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/templates/sports.php:5`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = 'd3be6efcb12a449c497d671557bbeb1e'; // limit hit for May 2022
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 330. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-signage/templates/sports.php:6`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$api_key = 'f837a07ab0344f6ec917fafdb0276ffa';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 331. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/forms_model.php:5636`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
if ( move_uploaded_file( $file['tmp_name'], $target['path'] ) ) {
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 332. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/form_display.php:460`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
if ( $file_info && move_uploaded_file( $_FILES[ $input_name ]['tmp_name'], $target_path . $file_info['temp_filename'] ) ) {
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 333. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/class-gf-upgrade.php:240`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$is_upgrading = $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name='gf_upgrade_lock'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 334. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/class-gf-upgrade.php:474`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$max    = $wpdb->query( "select id from {$table_name} order by id desc" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 335. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/class-gf-upgrade.php:1478`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = $wpdb->query( "UPDATE {$lead_details_table} SET value = TRIM(value)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 336. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/class-gf-upgrade.php:1480`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$results = $wpdb->get_results( "SELECT form_id, display_meta, confirmations, notifications FROM {$meta_table_name}", ARRAY_A );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 337. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/class-gf-upgrade.php:1582`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DROP INDEX {$index} ON {$table}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 338. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/class-gf-upgrade.php:1733`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$result = $wpdb->query( "ALTER TABLE {$lead_detail_table} MODIFY `value` LONGTEXT;" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 339. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/class-gf-upgrade.php:2058`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$lock_params_serialized = $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name='gf_upgrade_lock'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 340. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/class-gf-upgrade.php:2099`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$timestamp = $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name='gf_submissions_block'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 341. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/addon/class-gf-feed-addon.php:930`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->update( "{$wpdb->prefix}gf_addon_feed", array( 'meta' => $meta ), array( 'id' => $id ), array( '%s' ), array( '%d' ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 342. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/addon/class-gf-feed-addon.php:939`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->update( "{$wpdb->prefix}gf_addon_feed", array( 'is_active' => $is_active ), array( 'id' => $id ), array( '%d' ), array( '%d' ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 343. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/addon/class-gf-feed-addon.php:953`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->insert( "{$wpdb->prefix}gf_addon_feed", array( 'addon_slug' => $this->_slug, 'form_id' => $form_id, 'is_active' => $is_active, 'meta' => $meta ), array( '%s', '%d', '%d', '%s' ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 344. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/addon/class-gf-feed-addon.php:972`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->delete( "{$wpdb->prefix}gf_addon_feed", array( 'id' => $id ), array( '%d' ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 345. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/addon/class-gf-payment-addon.php:1746`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->insert( "{$wpdb->prefix}gf_addon_payment_callback", array(
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 346. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/addon/class-gf-payment-addon.php:3723`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->delete( "{$wpdb->prefix}gf_addon_payment_transaction", array( 'lead_id' => $entry_id ), array( '%d' ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 347. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/addon/class-gf-payment-addon.php:3726`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->delete( "{$wpdb->prefix}gf_addon_payment_callback", array( 'lead_id' => $entry_id ), array( '%d' ) );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 348. File upload without malware scanning detected

**File:** `/var/www/html/wordpress/wp-content/plugins/gravityforms/includes/fields/class-gf-field-fileupload.php:731`
**CWE:** CWE-434
**Confidence:** HIGH

**Description:**
File upload without malware scanning detected

**Code:**
```php
if ( move_uploaded_file( $file['tmp_name'], $target['path'] ) ) {
```

**Recommendation:**
Scan uploaded files with ClamAV or similar before moving to permanent location

---

#### 349. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/all-in-one-wp-migration/uninstall.php:50`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "DELETE FROM `{$wpdb->options}` WHERE `option_name` LIKE 'ai1wm\_%'" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 350. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/antispam-bee/inc/columns.class.php:109`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$reasons     = $wpdb->get_results( "SELECT meta_value FROM {$wpdb->prefix}commentmeta WHERE meta_key = 'antispam_bee_reason' group by meta_value", ARRAY_A );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 351. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-site-manager-host/cxq-site-manager-host.class.php:1261`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$cols = $wpdb->get_col( "DESC " . $wpdb->posts, 0 );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 352. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-site-manager-host/cxq-site-manager-host.class.php:2213`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$table_name}`
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 353. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-site-manager-host/cxq-site-manager-host.class.php:2218`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("ALTER TABLE `{$table_name}` CHANGE `log_id` `log_id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT;");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 354. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-site-manager-host/includes/core/cxq-site-manager-host-cloudflare.php:13`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
//protected $zone_api_token = '-xHZ2Ut7wyszICtT_MMJT9out0uHSltENvyi85Ic';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 355. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-site-manager-host/includes/core/cxq-site-manager-host-cloudflare.php:14`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
protected $api_key = '3b55771ba3f2a783a2baaa0c11f512b29c7d2';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 356. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-site-manager-host/includes/core/cxq-site-manager-host-lightsail.php:20`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$secret = 'v5UZpJWwVhFJjO2fe0BaobZw+K4gXIbASKjnOCu1';
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 357. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-api-rules.php:629`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$categories = $wpdb->get_col( "SELECT DISTINCT category FROM {$table_name} ORDER BY category" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 358. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-api-rules.php:630`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$types      = $wpdb->get_col( "SELECT DISTINCT rule_type FROM {$table_name} ORDER BY rule_type" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 359. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-api-rules.php:1027`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "TRUNCATE TABLE {$table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 360. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:168`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$this->table_name} ADD COLUMN sm_client_id BIGINT UNSIGNED DEFAULT NULL" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 361. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:169`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$this->table_name} ADD KEY sm_client_id (sm_client_id)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 362. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:466`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$columns = $wpdb->get_results( "SHOW COLUMNS FROM {$table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 363. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:473`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN source_category VARCHAR(30) NOT NULL DEFAULT 'auto_uncertain' AFTER confidence_level" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 364. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:478`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN original_client_verdict VARCHAR(20) DEFAULT NULL AFTER source_category" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 365. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:483`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN priority INT NOT NULL DEFAULT 50 AFTER original_client_verdict" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 366. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:484`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD KEY idx_priority (priority)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 367. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:489`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN client_submission_log_id BIGINT DEFAULT NULL AFTER priority" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 368. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:494`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN deferred_response_needed BOOLEAN DEFAULT FALSE AFTER client_submission_log_id" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 369. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:499`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN deferred_deadline DATETIME DEFAULT NULL AFTER deferred_response_needed" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 370. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:500`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD KEY idx_deferred_deadline (deferred_deadline)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 371. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:505`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN verdict_pushed_to_client BOOLEAN DEFAULT FALSE AFTER client_notified" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 372. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:510`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN verdict_push_attempts INT DEFAULT 0 AFTER verdict_pushed_to_client" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 373. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:515`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN verdict_pushed_at DATETIME DEFAULT NULL AFTER verdict_push_attempts" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 374. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:519`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$indexes = $wpdb->get_results( "SHOW INDEX FROM {$table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 375. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-client-manager.php:525`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "ALTER TABLE {$table_name} ADD KEY idx_source_category (source_category)" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 376. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-captcha-manager.php:182`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$results = $wpdb->get_results( "SELECT * FROM {$this->config_table}", ARRAY_A );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 377. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/includes/class-cxq-antispam-host-cli.php:185`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "TRUNCATE TABLE {$table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 378. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/admin/class-cxq-antispam-host-admin.php:723`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$rules = $wpdb->get_results( "SELECT * FROM {$rules_table} ORDER BY priority DESC, rule_name ASC" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 379. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/admin/class-cxq-antispam-host-admin.php:727`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$categories = $wpdb->get_col( "SELECT DISTINCT category FROM {$rules_table} ORDER BY category" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 380. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/admin/class-cxq-antispam-host-admin.php:728`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$types = $wpdb->get_col( "SELECT DISTINCT rule_type FROM {$rules_table} ORDER BY rule_type" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 381. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam-host/admin/class-cxq-antispam-host-admin.php:1084`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$clients = $wpdb->get_results( "SELECT id, client_name FROM {$clients_table} WHERE status = 'approved' ORDER BY client_name" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 382. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-scheduler/includes/api/class-cxq-api-client.php:139`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
// error_log('CxQ save_tokens: session_token = ' . substr($tokens['session_token'] ?? 'MISSING', 0, 30));
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 383. Hardcoded credentials detected

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-scheduler/includes/api/class-cxq-api-client.php:183`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
// error_log('CxQ load_tokens: session_token = ' . substr($sessionToken ?: 'EMPTY', 0, 30));
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 384. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-scheduler/includes/admin/purge-and-resync.php:270`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$event_ids = $wpdb->get_col("SELECT ID FROM {$wpdb->posts} WHERE post_type = 'cxq_external_event'");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 385. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-scheduler/includes/admin/purge-and-resync.php:284`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query("DELETE FROM {$wpdb->postmeta} WHERE post_id NOT IN (SELECT ID FROM {$wpdb->posts})");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 386. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam/includes/class-cxq-antispam-rules-sync.php:582`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$wpdb->query( "TRUNCATE TABLE {$this->rules_table}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 387. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-antispam/admin/class-cxq-antispam-admin.php:1228`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$form_types = $wpdb->get_col( "SELECT DISTINCT form_type FROM {$table_name}" );
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 388. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**File:** `/var/www/html/wordpress/wp-content/plugins/cxq-woocommerce-places/class-cxq-woocommerce-place-editor.php:18`
**CWE:** CWE-89
**Confidence:** HIGH

**Description:**
Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

**Code:**
```php
$locations = $wpdb->get_results("SELECT * FROM `{$this->table_names['locations']}` order by region, city /* (in ".__FILE__.':'.__LINE__." )*/");
```

**Recommendation:**
Use $wpdb->prepare() with placeholders instead of string concatenation

---

#### 389. Hardcoded credentials detected

**File:** `/opt/claude-workspace/projects/ecoeye-alert-relay/api-thumbnails.php:35`
**CWE:** CWE-798
**Confidence:** HIGH

**Description:**
Hardcoded credentials detected

**Code:**
```php
$valid_api_key = 'your-api-key-here'; // TODO: Replace with actual key
```

**Recommendation:**
Move credentials to environment variables or secure configuration

---

#### 390. Possible SQL injection: $wpdb method called with string concatenation instead of prepare()

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

#### 391. Deprecated mysql_query() with variable input

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

## Projects Summary

| Project | Files | Issues | CRITICAL | HIGH | MEDIUM | LOW |
|---------|-------|--------|----------|------|--------|-----|
| woocommerce | 2996 | 158 | 103 | 4 | 0 | 51 |
| wordfence | 383 | 76 | 60 | 0 | 0 | 16 |
| jetpack | 1351 | 70 | 11 | 5 | 0 | 54 |
| the-events-calendar | 1959 | 57 | 10 | 0 | 0 | 47 |
| worker | 316 | 51 | 17 | 0 | 0 | 34 |
| cxq-facebot | 292 | 46 | 31 | 0 | 0 | 15 |
| all-in-one-seo-pack-pro | 532 | 39 | 7 | 0 | 0 | 32 |
| gravityforms | 331 | 39 | 18 | 6 | 0 | 15 |
| archive | 537 | 39 | 1 | 3 | 0 | 35 |
| wpforms | 1161 | 33 | 8 | 8 | 0 | 17 |
| cxq-antispam-host | 23 | 28 | 25 | 0 | 0 | 3 |
| motopress-hotel-booking | 1035 | 27 | 4 | 5 | 0 | 18 |
| wpforms-lite | 3541 | 23 | 2 | 3 | 0 | 18 |
| cxq-signage | 50 | 22 | 18 | 0 | 0 | 4 |
| mailpoet | 3569 | 19 | 0 | 0 | 0 | 19 |
| wp-mail-smtp | 436 | 17 | 16 | 0 | 0 | 1 |
| cxq-site-manager-host | 254 | 16 | 6 | 0 | 0 | 10 |
| cxq-membership | 422 | 15 | 5 | 1 | 0 | 9 |
| woocommerce-product-addons | 87 | 15 | 0 | 3 | 0 | 12 |
| cxq-scheduler | 217 | 14 | 4 | 0 | 0 | 10 |
| cxq-updater-host | 18 | 11 | 1 | 0 | 0 | 10 |
| woocommerce-product-vendors | 363 | 10 | 10 | 0 | 0 | 0 |
| cxq-google-hours | 231 | 10 | 2 | 0 | 0 | 8 |
| cxq-firewall | 222 | 10 | 0 | 0 | 0 | 10 |
| cxq-antispam | 251 | 10 | 2 | 0 | 0 | 8 |
| cxq-email-relay | 226 | 9 | 3 | 0 | 0 | 6 |
| cxq-membership.backup-20260115 | 188 | 9 | 5 | 0 | 0 | 4 |
| google-analytics-for-wordpress | 213 | 8 | 3 | 0 | 0 | 5 |
| woocommerce-payments | 410 | 8 | 0 | 0 | 0 | 8 |
| cxq-event-calendar | 255 | 8 | 2 | 0 | 0 | 6 |
| antispam-bee | 3 | 8 | 1 | 0 | 0 | 7 |
| hestia-automation | 37 | 8 | 0 | 1 | 0 | 7 |
| cxq-board-docs | 224 | 6 | 0 | 0 | 0 | 6 |
| akismet | 22 | 5 | 5 | 0 | 0 | 0 |
| mphb-request-payment | 42 | 5 | 2 | 0 | 0 | 3 |
| all-in-one-wp-migration | 142 | 5 | 1 | 2 | 0 | 2 |
| distributor | 46 | 5 | 0 | 0 | 0 | 5 |
| mphb-notifier | 41 | 4 | 0 | 0 | 0 | 4 |
| cxq-cashdrawer | 54 | 3 | 0 | 0 | 0 | 3 |
| cxq-site-manager-client | 93 | 3 | 0 | 0 | 0 | 3 |
| cxq-license-manager | 9 | 3 | 0 | 0 | 0 | 3 |
| woocommerce-gateway-stripe | 143 | 2 | 0 | 0 | 0 | 2 |
| woocommerce-checkout-manager | 106 | 2 | 0 | 0 | 0 | 2 |
| cxq-cloudflare-manager | 2 | 2 | 2 | 0 | 0 | 0 |
| query-monitor | 141 | 2 | 0 | 0 | 0 | 2 |
| debug-bar | 10 | 2 | 0 | 0 | 0 | 2 |
| ecoeye-alert-relay | 7 | 2 | 1 | 0 | 0 | 1 |
| cxq-libs | 89 | 2 | 0 | 0 | 0 | 2 |
| gravityformsuserregistration | 12 | 1 | 1 | 0 | 0 | 0 |
| all-in-one-wp-migration-unlimited-extension | 15 | 1 | 1 | 0 | 0 | 0 |
| cxq-spec-auditor | 6 | 1 | 1 | 0 | 0 | 0 |
| cxq-doc-builder | 16 | 1 | 0 | 0 | 0 | 1 |
| pta-volunteer-sign-up-sheets | 35 | 1 | 0 | 0 | 0 | 1 |
| cxq-woocommerce-places | 19 | 1 | 1 | 0 | 0 | 0 |
| cxq-woocommerce-sales-list | 8 | 1 | 0 | 0 | 0 | 1 |
| cxq-woocommerce-product-map | 4 | 1 | 1 | 0 | 0 | 0 |

## Issues by Category

### WEAK CRYPTO (547 issues)

**CRITICAL:** 0, **HIGH:** 5

### SQL INJECTION (348 issues)

**CRITICAL:** 348, **HIGH:** 0

### FILE UPLOAD (46 issues)

**CRITICAL:** 10, **HIGH:** 36

### CREDENTIALS (33 issues)

**CRITICAL:** 33, **HIGH:** 0
