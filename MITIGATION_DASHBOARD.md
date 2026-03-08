# Security Mitigation Dashboard

**Generated:** 2026-03-08 00:00:53
**Source:** Blue Team Codebase Scanner
**Auto-updated:** Hourly

---

## Overview

| Metric | Count |
|--------|-------|
| Projects with Issues | 27 |
| **CRITICAL Issues** | **150** |
| **HIGH Issues** | **201** |
| MEDIUM Issues | 6 |
| **Total Issues** | **357** |

---

## Projects Requiring Attention

| Project | Critical | High | Medium | Total | TODO |
|---------|----------|------|--------|-------|------|
| wordfence | 47 | 2 | 0 | 49 | [TODO](/var/www/html/wordpress/wp-content/plugins/wordfence/TODO_SECURITY.md) |
| woocommerce | 42 | 34 | 1 | 77 | [TODO](/var/www/html/wordpress/wp-content/plugins/woocommerce/TODO_SECURITY.md) |
| gravityforms | 13 | 15 | 0 | 28 | [TODO](/var/www/html/wordpress/wp-content/plugins/gravityforms/TODO_SECURITY.md) |
| worker | 11 | 0 | 0 | 11 | [TODO](/var/www/html/wordpress/wp-content/plugins/worker/TODO_SECURITY.md) |
| jetpack | 10 | 32 | 0 | 42 | [TODO](/var/www/html/wordpress/wp-content/plugins/jetpack/TODO_SECURITY.md) |
| the-events-calendar | 6 | 0 | 0 | 6 | [TODO](/var/www/html/wordpress/wp-content/plugins/the-events-calendar/TODO_SECURITY.md) |
| wpforms | 4 | 25 | 0 | 29 | [TODO](/var/www/html/wordpress/wp-content/plugins/wpforms/TODO_SECURITY.md) |
| wp-mail-smtp | 4 | 0 | 0 | 4 | [TODO](/var/www/html/wordpress/wp-content/plugins/wp-mail-smtp/TODO_SECURITY.md) |
| woocommerce-product-vendors | 3 | 1 | 0 | 4 | [TODO](/var/www/html/wordpress/wp-content/plugins/woocommerce-product-vendors/TODO_SECURITY.md) |
| all-in-one-seo-pack-pro | 2 | 0 | 0 | 2 | [TODO](/var/www/html/wordpress/wp-content/plugins/all-in-one-seo-pack-pro/TODO_SECURITY.md) |
| wpforms-lite | 1 | 16 | 0 | 17 | [TODO](/var/www/html/wordpress/wp-content/plugins/wpforms-lite/TODO_SECURITY.md) |
| google-analytics-for-wordpress | 1 | 3 | 1 | 5 | [TODO](/var/www/html/wordpress/wp-content/plugins/google-analytics-for-wordpress/TODO_SECURITY.md) |
| cxq-woocommerce-product-map | 1 | 3 | 0 | 4 | [TODO](/opt/claude-workspace/projects/cxq-woocommerce-product-map/TODO_SECURITY.md) |
| archive | 1 | 3 | 0 | 4 | [TODO](/opt/claude-workspace/projects/archive/TODO_SECURITY.md) |
| gravityformsuserregistration | 1 | 0 | 0 | 1 | [TODO](/var/www/html/wordpress/wp-content/plugins/gravityformsuserregistration/TODO_SECURITY.md) |
| antispam-bee | 1 | 0 | 0 | 1 | [TODO](/var/www/html/wordpress/wp-content/plugins/antispam-bee/TODO_SECURITY.md) |
| ecoeye-alert-relay | 1 | 0 | 0 | 1 | [TODO](/opt/claude-workspace/projects/ecoeye-alert-relay/TODO_SECURITY.md) |
| dev-team-app | 1 | 0 | 0 | 1 | [TODO](/opt/claude-workspace/projects/dev-team-app/TODO_SECURITY.md) |
| pta-volunteer-sign-up-sheets | 0 | 15 | 4 | 19 | [TODO](/var/www/html/wordpress/wp-content/plugins/pta-volunteer-sign-up-sheets/TODO_SECURITY.md) |
| groundtruth-studio | 0 | 15 | 0 | 15 | [TODO](/opt/claude-workspace/projects/groundtruth-studio/TODO_SECURITY.md) |
| mphb-divi | 0 | 14 | 0 | 14 | [TODO](/var/www/html/wordpress/wp-content/plugins/mphb-divi/TODO_SECURITY.md) |
| motopress-hotel-booking | 0 | 10 | 0 | 10 | [TODO](/var/www/html/wordpress/wp-content/plugins/motopress-hotel-booking/TODO_SECURITY.md) |
| finance-manager | 0 | 5 | 0 | 5 | [TODO](/opt/claude-workspace/projects/finance-manager/TODO_SECURITY.md) |
| woocommerce-product-addons | 0 | 3 | 0 | 3 | [TODO](/var/www/html/wordpress/wp-content/plugins/woocommerce-product-addons/TODO_SECURITY.md) |
| all-in-one-wp-migration | 0 | 2 | 0 | 2 | [TODO](/var/www/html/wordpress/wp-content/plugins/all-in-one-wp-migration/TODO_SECURITY.md) |
| hestia-automation | 0 | 2 | 0 | 2 | [TODO](/opt/claude-workspace/projects/hestia-automation/TODO_SECURITY.md) |
| cyber-guardian | 0 | 1 | 0 | 1 | [TODO](/opt/claude-workspace/projects/cyber-guardian/TODO_SECURITY.md) |

---

## Quick Actions

**View all security TODOs:**
```bash
find /var/www/html/wordpress/wp-content/plugins -name 'TODO_SECURITY.md'
```

**Run new scan:**
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 blueteam/cli_codebase_scan.py
```

**Generate fresh TODOs:**
```bash
python3 scripts/generate-mitigation-todos.py
```

