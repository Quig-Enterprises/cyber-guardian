#!/usr/bin/env python3
"""Demo: CVE verification with mock nginx config responses.

This demonstrates what verification looks like when configs ARE accessible.
"""

import asyncio
from redteam.cve.verifiers.nginx import NginxCVEVerifier
from redteam.cve.parsers.nginx_parser import NginxConfigParser


# Mock client that returns nginx configs
class MockClient:
    def __init__(self, config_response=None):
        self.config_response = config_response

    async def get(self, path, cookies=None):
        if self.config_response and "nginx" in path.lower():
            return (200, self.config_response, {})
        return (404, "", {})


# Test configs
VULNERABLE_CONFIG = r"""
server {
    listen 80;
    server_name example.com;
    root /var/www/html;

    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php-fpm.sock;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
"""

SAFE_CONFIG = r"""
server {
    listen 80;
    server_name example.com;
    root /var/www/html;

    location ~ \.php$ {
        fastcgi_pass unix:/run/php-fpm.sock;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
"""


async def demo_vulnerable_config():
    """Demo: CVE-2019-11043 with VULNERABLE config."""
    print("\n" + "=" * 70)
    print("DEMO 1: CVE-2019-11043 with VULNERABLE nginx config")
    print("=" * 70)

    config = {
        "cve": {
            "verification": {
                "enabled": True,
                "aggressiveness": "low",
                "config_endpoints": {"nginx": ["/nginx.conf"]},
                "specific_cves": {"CVE-2019-11043": True}
            }
        }
    }

    client = MockClient(config_response=VULNERABLE_CONFIG)
    verifier = NginxCVEVerifier(config)

    result = await verifier.verify(client, "CVE-2019-11043", "nginx", "1.24.0")

    print(f"\nCVE ID: {result.cve_id}")
    print(f"Status: {'VULNERABLE' if result.verified_vulnerable else 'DEFENDED' if result.verified_defended else 'UNVERIFIED'}")
    print(f"Evidence: {result.evidence}")
    print(f"Config Source: {result.config_source}")
    print(f"Confidence: {result.confidence}")

    assert result.verified_vulnerable, "Should detect vulnerable pattern"
    assert result.confidence == "high", "Should have high confidence"
    print("\n✅ Test PASSED: Vulnerable config correctly identified")


async def demo_safe_config():
    """Demo: CVE-2019-11043 with SAFE config."""
    print("\n" + "=" * 70)
    print("DEMO 2: CVE-2019-11043 with SAFE nginx config")
    print("=" * 70)

    config = {
        "cve": {
            "verification": {
                "enabled": True,
                "aggressiveness": "low",
                "config_endpoints": {"nginx": ["/nginx.conf"]},
                "specific_cves": {"CVE-2019-11043": True}
            }
        }
    }

    client = MockClient(config_response=SAFE_CONFIG)
    verifier = NginxCVEVerifier(config)

    result = await verifier.verify(client, "CVE-2019-11043", "nginx", "1.24.0")

    print(f"\nCVE ID: {result.cve_id}")
    print(f"Status: {'VULNERABLE' if result.verified_vulnerable else 'DEFENDED' if result.verified_defended else 'UNVERIFIED'}")
    print(f"Evidence: {result.evidence}")
    print(f"Config Source: {result.config_source}")
    print(f"Confidence: {result.confidence}")

    assert result.verified_defended, "Should mark as defended"
    assert result.confidence == "high", "Should have high confidence"
    print("\n✅ Test PASSED: Safe config correctly identified")


async def demo_no_config():
    """Demo: CVE-2019-11043 with NO accessible config."""
    print("\n" + "=" * 70)
    print("DEMO 3: CVE-2019-11043 with NO accessible config")
    print("=" * 70)

    config = {
        "cve": {
            "verification": {
                "enabled": True,
                "aggressiveness": "low",
                "config_endpoints": {"nginx": ["/nginx.conf"]},
                "specific_cves": {"CVE-2019-11043": True}
            }
        }
    }

    client = MockClient(config_response=None)  # No config returned
    verifier = NginxCVEVerifier(config)

    result = await verifier.verify(client, "CVE-2019-11043", "nginx", "1.24.0")

    print(f"\nCVE ID: {result.cve_id}")
    print(f"Status: {'VULNERABLE' if result.verified_vulnerable else 'DEFENDED' if result.verified_defended else 'UNVERIFIED'}")
    print(f"Evidence: {result.evidence}")
    print(f"Config Source: {result.config_source}")
    print(f"Confidence: {result.confidence}")

    assert result.confidence == "none", "Should have no confidence"
    print("\n✅ Test PASSED: Config inaccessibility correctly reported")


async def demo_parser():
    """Demo: Nginx config parser detection."""
    print("\n" + "=" * 70)
    print("DEMO 4: Nginx Config Parser Pattern Detection")
    print("=" * 70)

    print("\nParsing VULNERABLE config...")
    parser_vuln = NginxConfigParser(VULNERABLE_CONFIG)
    has_vuln = parser_vuln.has_vulnerable_fastcgi_split_path_info()
    php_locations = parser_vuln.find_php_locations()

    print(f"  Has vulnerable pattern: {has_vuln}")
    print(f"  PHP locations found: {len(php_locations)}")
    if php_locations:
        print(f"  First location pattern: {php_locations[0]['pattern'].strip()}")
        split_value = parser_vuln.get_directive_value(php_locations[0], "fastcgi_split_path_info")
        print(f"  fastcgi_split_path_info value: {split_value}")

    print("\nParsing SAFE config...")
    parser_safe = NginxConfigParser(SAFE_CONFIG)
    has_vuln_safe = parser_safe.has_vulnerable_fastcgi_split_path_info()
    print(f"  Has vulnerable pattern: {has_vuln_safe}")

    assert has_vuln, "Should detect vulnerable pattern"
    assert not has_vuln_safe, "Should NOT detect pattern in safe config"
    print("\n✅ Test PASSED: Parser correctly distinguishes configs")


async def main():
    """Run all demos."""
    print("\n" + "=" * 70)
    print("CVE Configuration Verification - Success Demonstration")
    print("=" * 70)
    print("\nThis demo shows what verification looks like when nginx configs")
    print("ARE accessible and can be parsed for vulnerable patterns.")

    await demo_vulnerable_config()
    await demo_safe_config()
    await demo_no_config()
    await demo_parser()

    print("\n" + "=" * 70)
    print("ALL DEMOS PASSED ✅")
    print("=" * 70)
    print("\nKey Takeaways:")
    print("1. VULNERABLE configs are correctly identified with HIGH confidence")
    print("2. SAFE configs are correctly marked as DEFENDED with HIGH confidence")
    print("3. Inaccessible configs are reported with NONE confidence (PARTIAL status)")
    print("4. Parser accurately detects vulnerable fastcgi_split_path_info patterns")
    print("\n")


if __name__ == "__main__":
    asyncio.run(main())
