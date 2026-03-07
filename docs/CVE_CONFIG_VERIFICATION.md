# CVE Configuration Verification

## Overview

The CVE Configuration Verification system performs "second-pass" verification of CVEs flagged by the scanner. Instead of relying solely on version matching, it checks actual configuration files to determine if vulnerable configuration patterns are present. This significantly reduces false positives.

**Example:** The scanner detects nginx 1.24.0 and flags CVE-2019-11043. The verification system checks the nginx configuration and confirms that the vulnerable `fastcgi_split_path_info` directive is absent, marking the system as DEFENDED rather than VULNERABLE.

## Architecture

### Components

1. **Shared State** (`redteam/state.py`)
   - Thread-safe storage for CVE findings across attacks
   - Allows later attacks to verify earlier findings

2. **Verifiers** (`redteam/cve/verifiers/`)
   - `base.py` - Abstract base class for all verifiers
   - `nginx.py` - Nginx configuration verification
   - `php.py` - PHP runtime/configuration verification
   - Extensible design for future verifiers

3. **Parsers** (`redteam/cve/parsers/`)
   - `nginx_parser.py` - Parses nginx config for security patterns
   - Simple, focused parsers (not full config parsers)

4. **Attack Module** (`redteam/attacks/cve/config_verification.py`)
   - Runs after other CVE attacks
   - Routes CVEs to appropriate verifiers
   - Generates verification results

## Workflow

```
1. CVE Attacks (server_cve, wp_plugin_cve, etc.)
   ├─> Detect software versions
   ├─> Query CVE databases
   ├─> Store findings in ScanState
   └─> Report potential vulnerabilities

2. Config Verification Attack
   ├─> Read findings from ScanState
   ├─> For each CVE with a verifier:
   │   ├─> Fetch relevant config files
   │   ├─> Parse for vulnerable patterns
   │   └─> Return verification result
   └─> Report verified vulnerabilities
```

## Supported CVEs

### Nginx
- **CVE-2019-11043** - PHP-FPM underflow RCE
  - Checks for vulnerable `fastcgi_split_path_info` pattern
  - Confidence: HIGH

- **CVE-2013-4547** - Space parsing vulnerability
  - Version-based verification
  - Confidence: MEDIUM

### PHP
- **CVE-2024-4577** - Windows CGI argument injection
  - Checks OS (Windows-only) and SAPI mode (CGI)
  - Confidence: HIGH (if phpinfo accessible)

- **CVE-2016-10033** - PHPMailer RCE
  - Checks for PHPMailer presence and version
  - Confidence: HIGH (if composer.json accessible)

## Configuration

### Enable/Disable Verification

```yaml
# redteam/config.yaml
cve:
  verification:
    enabled: true  # Set to false to disable all verification
```

### Aggressiveness Levels

```yaml
cve:
  verification:
    aggressiveness: "low"  # "low" | "medium" | "high"
```

- **low** (default): Only checks exposed admin endpoints
  - Safe for production scanning
  - Least intrusive

- **medium**: Attempts common misconfigurations
  - Includes paths like `/nginx.conf`, `/.htaccess`
  - Still passive

- **high**: Includes directory traversal probes
  - **WARNING:** Use only in controlled lab environments
  - Never use against production systems

### Custom Config Endpoints

```yaml
cve:
  verification:
    config_endpoints:
      nginx:
        - "/admin/nginx/config"
        - "/admin/config"
        - "/nginx.conf"
      php:
        - "/phpinfo.php"
        - "/?phpinfo=1"
        - "/admin/phpinfo.php"
```

### Disable Specific CVE Verification

```yaml
cve:
  verification:
    specific_cves:
      CVE-2019-11043: false  # Disable verification for this CVE
      CVE-2024-4577: true
```

## Verification Results

### Result Types

1. **VERIFIED VULNERABLE**
   - Configuration IS vulnerable
   - Exploit is possible
   - High confidence

2. **VERIFIED DEFENDED**
   - Configuration has mitigations
   - Exploit is NOT possible
   - High confidence

3. **UNVERIFIED**
   - Cannot access config for verification
   - Original CVE finding stands
   - Low/no confidence

### Confidence Levels

- **high**: Config accessed and parsed successfully
- **medium**: Indirect verification (version checks, headers)
- **low**: Limited information available
- **none**: Verification not attempted or failed

## Usage Examples

### Basic Scan with Verification

```bash
cd /opt/claude-workspace/projects/cyber-guardian
source venv/bin/activate

# Scan with CVE verification enabled (default)
python3 redteam/runner.py \
    --category cve \
    --target generic \
    --report console json
```

### Disable Verification

```bash
# Edit config.yaml to disable verification
sed -i 's/enabled: true/enabled: false/' redteam/config.yaml

# Or create a custom config file
python3 redteam/runner.py \
    --category cve \
    --config config-no-verify.yaml
```

### High Aggressiveness (Lab Only)

```yaml
# config-lab.yaml
cve:
  verification:
    enabled: true
    aggressiveness: "high"
```

```bash
python3 redteam/runner.py \
    --category cve \
    --config config-lab.yaml
```

## Output Examples

### Console Output

```
Running: cve.server_cve (cve)
  -> 1 vulnerable, 0 partial, 0 defended (234ms)

Running: cve.config_verification (cve)
  -> 0 vulnerable, 0 partial, 1 defended (156ms)

Results:
  ✗ cve.server_cve/nginx/CVE-2019-11043 [VULNERABLE]
    Evidence: CVE-2019-11043 (CVSS 9.8, risk 8.5) [CISA KEV]

  ✓ cve.config_verification/nginx/CVE-2019-11043 [DEFENDED]
    Evidence: [VERIFIED DEFENDED] PHP-FPM configured but no vulnerable
              fastcgi_split_path_info pattern (confidence: high)
```

### JSON Report

```json
{
  "attack_name": "cve.config_verification",
  "variant": "config_verification/nginx/CVE-2019-11043",
  "status": "defended",
  "severity": "info",
  "evidence": "[VERIFIED DEFENDED] PHP-FPM configured but no vulnerable fastcgi_split_path_info pattern (confidence: high)",
  "details": "nginx 1.24.0: ...\nConfig source: nginx.conf\nRisk score: 8.5"
}
```

## Adding New Verifiers

### Step 1: Create Verifier Class

```python
# redteam/cve/verifiers/apache.py
from .base import CVEVerifier, VerificationResult

class ApacheCVEVerifier(CVEVerifier):
    VERIFIABLE_CVES = {
        "CVE-2021-41773": "_verify_cve_2021_41773",
    }

    def can_verify(self, cve_id: str) -> bool:
        return cve_id in self.VERIFIABLE_CVES and self._is_enabled(cve_id)

    async def verify(self, client, cve_id, software, version):
        method_name = self.VERIFIABLE_CVES[cve_id]
        method = getattr(self, method_name)
        return await method(client, version)

    async def _verify_cve_2021_41773(self, client, version):
        # Implementation here
        ...
```

### Step 2: Register Verifier

```python
# redteam/cve/verifiers/__init__.py
from .apache import ApacheCVEVerifier

__all__ = [..., "ApacheCVEVerifier"]
```

### Step 3: Add to Config Verification Attack

```python
# redteam/attacks/cve/config_verification.py
from redteam.cve.verifiers import NginxCVEVerifier, PHPCVEVerifier, ApacheCVEVerifier

class ConfigVerificationAttack(Attack):
    def __init__(self):
        super().__init__()
        self._verifiers = []

    async def execute(self, client):
        self._verifiers = [
            NginxCVEVerifier(self._config),
            PHPCVEVerifier(self._config),
            ApacheCVEVerifier(self._config),  # NEW
        ]
        # ... rest of implementation
```

## Testing

### Unit Tests

```bash
# Test the Nginx parser
python3 test_config_verification.py
```

### Integration Tests

```bash
# Test against a known vulnerable configuration
# 1. Set up test nginx instance with vulnerable config
# 2. Run scanner
python3 redteam/runner.py --category cve --target generic

# 3. Verify results show DEFENDED after config verification
```

## Performance

- **Overhead**: ~100-200ms per CVE verified
- **Network Requests**: 3-5 per CVE (config endpoint probes)
- **Memory**: Minimal (configs are parsed and discarded)

## Security Considerations

1. **Passive by Default**: Low aggressiveness is safe for production
2. **No Modification**: Verifiers never modify configurations
3. **Credential-Free**: Does not require authentication to config endpoints
4. **Rate Limiting**: Respects existing request throttling

## Limitations

1. **Config Access**: Cannot verify if config files are not exposed
2. **Complex Configs**: May not handle advanced nginx includes/imports
3. **Runtime State**: Cannot detect runtime-only mitigations
4. **Custom Builds**: May not account for patched custom builds

## Future Enhancements

1. **More CVE Coverage**: Add verifiers for Apache, IIS, etc.
2. **Remote Config Fetching**: SSH/API-based config retrieval
3. **Auto-Remediation**: Generate config patches to fix vulnerabilities
4. **ML Pattern Detection**: Learn from config patterns
5. **Compliance Mapping**: Map CVEs to compliance frameworks

## Troubleshooting

### Issue: "No CVEs found by previous attacks"

**Cause:** Config verification runs after CVE attacks. If no CVEs were found, there's nothing to verify.

**Solution:** Ensure CVE attacks are running and finding vulnerabilities first.

### Issue: "Cannot access nginx config for verification"

**Cause:** Config files are not exposed on common endpoints.

**Solution:**
- Increase aggressiveness (use with caution)
- Add custom config endpoints to config.yaml
- Accept that verification cannot be performed

### Issue: "Verification shows UNVERIFIED"

**Cause:** Verifier attempted but couldn't access necessary information.

**Solution:** This is normal when configs are not exposed. The original CVE finding remains valid.

## References

- [CVE-2019-11043 Details](https://nvd.nist.gov/vuln/detail/CVE-2019-11043)
- [Nginx Configuration Documentation](https://nginx.org/en/docs/)
- [PHP Security Advisories](https://www.php.net/security/)
