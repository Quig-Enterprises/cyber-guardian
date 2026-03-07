#!/usr/bin/env python3
"""Quick test for CVE configuration verification."""

from redteam.cve.parsers.nginx_parser import NginxConfigParser

# Test case 1: Vulnerable nginx config (CVE-2019-11043)
vulnerable_config = r"""
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

# Test case 2: Safe nginx config (no vulnerable pattern)
safe_config = r"""
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

# Test case 3: No PHP handling
no_php_config = """
server {
    listen 80;
    server_name example.com;
    root /var/www/html;

    location / {
        try_files $uri $uri/ =404;
    }
}
"""

print("Testing Nginx Config Parser...")
print("=" * 60)

# Test vulnerable config
print("\n1. Testing VULNERABLE config:")
parser = NginxConfigParser(vulnerable_config)
has_vuln = parser.has_vulnerable_fastcgi_split_path_info()
print(f"   Has vulnerable pattern: {has_vuln}")
assert has_vuln, "Should detect vulnerable pattern"
print("   ✓ PASS: Vulnerable pattern detected")

# Test safe config
print("\n2. Testing SAFE config:")
parser = NginxConfigParser(safe_config)
has_vuln = parser.has_vulnerable_fastcgi_split_path_info()
print(f"   Has vulnerable pattern: {has_vuln}")
assert not has_vuln, "Should NOT detect vulnerable pattern"
print("   ✓ PASS: No vulnerable pattern detected")

# Test no PHP config
print("\n3. Testing NO PHP config:")
parser = NginxConfigParser(no_php_config)
has_vuln = parser.has_vulnerable_fastcgi_split_path_info()
has_fastcgi = parser.has_fastcgi_config()
print(f"   Has vulnerable pattern: {has_vuln}")
print(f"   Has fastcgi config: {has_fastcgi}")
assert not has_vuln, "Should NOT detect vulnerable pattern"
assert not has_fastcgi, "Should NOT have fastcgi config"
print("   ✓ PASS: No PHP handling detected")

# Test PHP location detection
print("\n4. Testing PHP location detection:")
parser = NginxConfigParser(vulnerable_config)
php_locations = parser.find_php_locations()
print(f"   Found {len(php_locations)} PHP location blocks")
assert len(php_locations) > 0, "Should find PHP locations"
print(f"   PHP location pattern: {php_locations[0]['pattern']}")
print(f"   Number of directives: {len(php_locations[0]['directives'])}")
print("   ✓ PASS: PHP locations detected")

print("\n" + "=" * 60)
print("All tests passed! ✓")
