#!/usr/bin/env python3
"""
WordPress Log Accessibility Scanner
Version: 1.0.0
Date: 2026-03-11

Scans WordPress sites for publicly accessible log files.
Tests common log file paths via HTTP and reports security vulnerabilities.

Usage:
    python3 wordpress-log-scanner.py --server peter
    python3 wordpress-log-scanner.py --sites pickerel-pearson.com,lakelucernewi.org

Returns:
    Exit 0: All log files protected
    Exit 1: Vulnerable log files found
"""

import argparse
import logging
import sys
import subprocess
import json
import urllib.request
import urllib.error
import ssl
from typing import List, Dict, Tuple
from datetime import datetime
from pathlib import Path

# Common WordPress log file paths to test
LOG_PATHS = [
    # Debug logs
    "/wp-content/debug.log",
    "/wp-content/debug_log",
    "/debug.log",

    # CxQ plugin logs
    "/wp-content/uploads/cxq-antispam-fallback.log",
    "/wp-content/cxq-logs/antispam.log",
    "/wp-content/cxq-logs/membership.log",
    "/wp-content/cxq-logs/firewall.log",

    # WooCommerce logs (should be protected)
    "/wp-content/uploads/wc-logs/fatal-errors.log",

    # Error logs
    "/error_log",
    "/error.log",
    "/php-error.log",

    # Plugin logs (common patterns)
    "/wp-content/uploads/error_log",
    "/wp-content/uploads/php_errors.log",
    "/wp-content/uploads/wp-errors.log",

    # Security plugin logs
    "/wp-content/uploads/sucuri/sucuri-auditqueue.php",
    "/wp-content/uploads/sucuri/sucuri-failedlogins.php",

    # Backup logs
    "/wp-content/ai1wm-backups/error.log",
    "/wp-content/backup-logs/backup.log",
]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("wordpress-log-scanner")


def get_sites_from_server(server: str) -> List[str]:
    """Get list of WordPress sites from server via SSH."""
    if server == "alfred":
        # Alfred is localhost
        cmd = ["find", "/var/www/html/wordpress/wp-content/plugins", "-maxdepth", "1", "-type", "d"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        # Alfred doesn't host WordPress sites, skip
        return []

    elif server == "peter":
        # Peter (cp.quigs.com) - get sites from Hestia
        cmd = [
            "ssh", "-i", f"{Path.home()}/.ssh/webhost_key",
            "ubuntu@webhost.tailce791f.ts.net",
            "find /home/brandon/web -maxdepth 1 -type d -name '*.com' -o -name '*.org' -o -name '*.net' | xargs -I {} basename {}"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            sites = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            logger.info(f"Found {len(sites)} sites on {server}")
            return sites
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get sites from {server}: {e}")
            return []

    return []


def test_log_accessibility(domain: str, log_path: str, timeout: int = 5) -> Tuple[int, str]:
    """Test if a log file is publicly accessible.

    Returns:
        Tuple of (status_code, content_type)
        status_code: HTTP status code (200=accessible, 403=forbidden, 404=not found)
        content_type: Content-Type header value
    """
    url = f"https://{domain}{log_path}"

    try:
        # Create SSL context that doesn't verify certificates (for testing)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, method='HEAD')
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            status = response.status
            content_type = response.headers.get('Content-Type', '')
            return (status, content_type)

    except urllib.error.HTTPError as e:
        return (e.code, '')
    except Exception as e:
        logger.debug(f"Error testing {url}: {e}")
        return (0, '')


def scan_site(domain: str) -> Dict:
    """Scan a single WordPress site for accessible log files.

    Returns:
        Dict with scan results:
        {
            'domain': str,
            'scan_time': str,
            'vulnerable_logs': List[Dict],
            'protected_logs': List[str],
            'total_tested': int
        }
    """
    logger.info(f"Scanning {domain}...")

    vulnerable = []
    protected = []

    for log_path in LOG_PATHS:
        status, content_type = test_log_accessibility(domain, log_path)

        if status == 200:
            # File is accessible - VULNERABLE
            vulnerable.append({
                'path': log_path,
                'url': f"https://{domain}{log_path}",
                'content_type': content_type,
                'severity': 'HIGH' if 'debug' in log_path.lower() or 'error' in log_path.lower() else 'MEDIUM'
            })
            logger.warning(f"  VULNERABLE: {log_path} (HTTP {status})")

        elif status == 403:
            # File exists but is forbidden - PROTECTED
            protected.append(log_path)
            logger.debug(f"  Protected: {log_path} (HTTP 403)")

        # 404 means file doesn't exist or is completely blocked - OK

    return {
        'domain': domain,
        'scan_time': datetime.now().astimezone().isoformat(),
        'vulnerable_logs': vulnerable,
        'protected_logs': protected,
        'total_tested': len(LOG_PATHS),
        'status': 'VULNERABLE' if vulnerable else 'SECURE'
    }


def main():
    parser = argparse.ArgumentParser(description='Scan WordPress sites for publicly accessible log files')
    parser.add_argument('--server', choices=['alfred', 'peter', 'willie'],
                       help='Server to scan (auto-discovers sites)')
    parser.add_argument('--sites', help='Comma-separated list of domains to scan')
    parser.add_argument('--output', help='Output JSON file path')
    parser.add_argument('--quiet', action='store_true', help='Suppress informational output')

    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    # Get sites to scan
    sites = []
    if args.sites:
        sites = [s.strip() for s in args.sites.split(',')]
    elif args.server:
        sites = get_sites_from_server(args.server)
    else:
        logger.error("Must specify --server or --sites")
        return 1

    if not sites:
        logger.error("No sites to scan")
        return 1

    logger.info(f"Scanning {len(sites)} sites...")

    # Scan all sites
    results = []
    vulnerable_count = 0

    for site in sites:
        result = scan_site(site)
        results.append(result)

        if result['vulnerable_logs']:
            vulnerable_count += 1

    # Generate summary
    total_vulnerable_logs = sum(len(r['vulnerable_logs']) for r in results)

    summary = {
        'scan_time': datetime.now().astimezone().isoformat(),
        'scanner_version': '1.0.0',
        'total_sites': len(sites),
        'vulnerable_sites': vulnerable_count,
        'total_vulnerable_logs': total_vulnerable_logs,
        'sites': results
    }

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"Results written to {args.output}")
    else:
        print(json.dumps(summary, indent=2))

    # Print summary to stderr
    print("\n" + "="*60, file=sys.stderr)
    print("WordPress Log Accessibility Scan Summary", file=sys.stderr)
    print("="*60, file=sys.stderr)
    print(f"Sites scanned: {len(sites)}", file=sys.stderr)
    print(f"Vulnerable sites: {vulnerable_count}", file=sys.stderr)
    print(f"Total vulnerable log files: {total_vulnerable_logs}", file=sys.stderr)

    if vulnerable_count > 0:
        print(f"\nVULNERABLE SITES:", file=sys.stderr)
        for result in results:
            if result['vulnerable_logs']:
                print(f"\n{result['domain']}:", file=sys.stderr)
                for log in result['vulnerable_logs']:
                    print(f"  [{log['severity']}] {log['url']}", file=sys.stderr)
        print("\n⚠️  REMEDIATION: Add .htaccess protection to wp-content/uploads/", file=sys.stderr)
        return 1
    else:
        print("\n✓ All sites secure - no publicly accessible log files found", file=sys.stderr)
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        sys.exit(130)
