# Cyber-Guardian TODO

## Features

### Remote Domain Scanning via Direct Origin IP

**Status:** NOT STARTED
**Priority:** MEDIUM

**Description:**
Add the ability to run red team security scans against any domain hosted on a webserver by bypassing Cloudflare (or other CDN/WAF proxies) and hitting the origin server IP directly with a custom `Host` header.

**Use Case:**
When domains are behind Cloudflare (e.g., CNAME to `cp.quigs.com`), normal scans hit Cloudflare's edge, not the actual server. This feature allows scanning the real origin to find vulnerabilities that Cloudflare may be masking.

**Example Usage:**
```bash
# Via the primary runner (recommended)
python -m redteam.runner --target https://example.com --origin-ip 1.2.3.4

# Via the unified CLI
cyber-guardian redteam --target https://example.com --origin-ip 1.2.3.4

# Via shell wrapper
bin/run-redteam.sh --target https://example.com --origin-ip 1.2.3.4

# Via config.yaml (no CLI flag needed)
# Set target.origin_ip in config.yaml or config.local.yaml
```

---

#### Architecture Overview

The scan system uses a **single shared HTTP client** (`RedTeamClient`) passed to every attack module via `execute(client)`. All HTTP requests flow through `client.get()`, `client.post()`, and `client.delete()`. This means Host header injection can be done in **one place** (the client) and all ~30+ attack modules benefit automatically with zero changes.

`WordPressClient` inherits from `RedTeamClient` and does not override the HTTP methods, so changes propagate to WordPress scanning automatically.

SSL verification is already disabled (`aiohttp.TCPConnector(ssl=False)` in `client.py:51`), so HTTPS connections to an origin IP will work without certificate errors.

---

#### Files to Modify

| # | File | Change |
|---|------|--------|
| 1 | `redteam/client.py` | **Core change.** Modify `RedTeamClient.__init__()` to accept `origin_ip` param. When set: rewrite `self.base_url` to use origin IP as host, store original hostname, inject `Host: <original_hostname>` into every `get()`, `post()`, `delete()` call. |
| 2 | `redteam/wp_client.py` | Thread `origin_ip` param through `WordPressClient.__init__()` to `super().__init__()`. |
| 3 | `redteam/runner.py` | Add `--origin-ip` to `parse_args()` (after line 123). Inject into config dict before client creation (~line 247). Pass `origin_ip` when constructing `RedTeamClient`/`WordPressClient` (~line 252). |
| 4 | `cyberguardian/cli.py` | Add `--origin-ip` to the `redteam` subparser (lines 49-55) for unified CLI parity. |
| 5 | `config.yaml` | Add `target.origin_ip: null` field with documentation comment. |

**Files that do NOT need changes:**
- `redteam/attacks/**` — all attack modules use the shared client; no per-module changes needed
- `redteam/registry.py` — attack discovery is unaffected
- `redteam/base.py` — base `Attack` class is unaffected
- `redteam/state.py` — scan state is unaffected
- `shared/config.py` — config loading handles new keys automatically via deep-merge
- `bin/run-redteam.sh` — passes `$@` to runner, so `--origin-ip` works with no changes

---

#### Implementation Details

**Step 1 — `redteam/client.py` (core logic):**

Modify `RedTeamClient.__init__()`:
```python
def __init__(self, base_url: str, timeout: int = 180, origin_ip: str = None):
    from urllib.parse import urlparse, urlunparse
    self._original_base_url = base_url.rstrip("/")
    self._origin_ip = origin_ip
    self._host_header = None

    if origin_ip:
        parsed = urlparse(base_url)
        self._host_header = parsed.hostname  # e.g. "example.com"
        port = parsed.port
        netloc = origin_ip if not port else f"{origin_ip}:{port}"
        self.base_url = urlunparse(parsed._replace(netloc=netloc)).rstrip("/")
    else:
        self.base_url = self._original_base_url
```

Inject `Host` header in each HTTP method (`get`, `post`, `delete`):
```python
async def get(self, path, params=None, headers=None, cookies=None):
    req_headers = dict(headers or {})
    if self._host_header and "Host" not in req_headers:
        req_headers["Host"] = self._host_header
    # ... rest unchanged ...
```

**Step 2 — `redteam/wp_client.py`:**

Forward `origin_ip` through `WordPressClient.__init__()`:
```python
def __init__(self, base_url, wp_config=None, origin_ip=None):
    super().__init__(base_url, origin_ip=origin_ip)
    # ... rest unchanged ...
```

**Step 3 — `redteam/runner.py`:**

Add CLI arg in `parse_args()` (after line 123):
```python
parser.add_argument(
    "--origin-ip",
    type=str,
    default=None,
    metavar="IP",
    help="Connect directly to this IP instead of resolving the hostname "
         "(bypasses Cloudflare/CDN). Sets Host header to the hostname from base_url.",
)
```

Inject into config (~line 247, before client creation):
```python
if args.origin_ip:
    config.setdefault("target", {})["origin_ip"] = args.origin_ip
```

Pass to client (~line 252):
```python
origin_ip = config.get("target", {}).get("origin_ip")
if "wordpress" in target_types:
    client = WordPressClient(base_url, wp_config=wp_cfg, origin_ip=origin_ip)
else:
    client = RedTeamClient(base_url, origin_ip=origin_ip)
```

**Step 4 — `config.yaml`:**
```yaml
target:
  base_url: "http://localhost:8081"
  api_path: "/api"
  origin_ip: null  # Set to an IP to bypass DNS/CDN and connect directly (e.g. "1.2.3.4")
```

---

#### Acceptance Criteria

- [ ] `python -m redteam.runner --target https://example.com --origin-ip 1.2.3.4` connects to `1.2.3.4` with `Host: example.com` header
- [ ] All attack modules (generic, app, wordpress) use the origin IP transparently
- [ ] HTTPS targets work without certificate errors (SSL verification already disabled)
- [ ] `config.yaml` / `config.local.yaml` `target.origin_ip` field works as alternative to CLI flag
- [ ] CLI flag overrides config file value
- [ ] When `origin_ip` is not set, behavior is identical to current (no regression)
- [ ] Scan report indicates when origin-direct mode was used

---

### Multi-Target Versatility (CLI Target Override, Profiles, Static Scan)

**Status:** NOT STARTED
**Priority:** HIGH

**Description:**
Cyber-guardian is currently hard-coded to scan a single project (eqmon at `localhost:8081`) via `config.yaml`. The `base_url` is always read from `config["target"]["base_url"]` (`runner.py:247`) with no CLI override. The tool should be versatile enough to scan any target — different URLs, WordPress deployments, or local source directories — without editing config files.

**Current Blocker:**
Running `cyber-guardian redteam --category web` against a WordPress site (e.g., `cxq-membership`) is not possible without editing `config.yaml` to change `base_url`, which breaks the existing eqmon configuration.

---

#### Feature 1: CLI URL Override (`--url`)

**What:** Allow `--url` flag to override `config.yaml`'s `target.base_url` at runtime.

**Example Usage:**
```bash
# Scan a WordPress sandbox instead of the default eqmon target
python -m redteam.runner --category web --url http://sandbox.quigs.com

# Scan with target type override
python -m redteam.runner --target wordpress --url https://192.168.50.20/wordpress

# Combined with origin-ip feature
python -m redteam.runner --url https://example.com --origin-ip 1.2.3.4
```

**Files to Modify:**

| File | Change |
|------|--------|
| `redteam/runner.py` | Add `--url` flag to `parse_args()` (after line 106, near existing `--target`). In `run()`, if `args.url` is set, override `config["target"]["base_url"]` before client creation at line 247. |
| `cyberguardian/cli.py` | Add `--url` to `redteam` subparser (lines 49-55) for parity. Currently missing `--target`, `--mode`, `--config`, `--output`, `--verbose` too — consider adding all at once. |
| `redteam/cli.py` | Thread `--url` through `run_redteam()` (the adapter called by `cyberguardian/cli.py`). |

**Implementation in `runner.py`:**
```python
# In parse_args(), after --target (line 106):
parser.add_argument(
    "--url",
    type=str,
    default=None,
    metavar="URL",
    help="Target base URL. Overrides config.yaml target.base_url. "
         "Example: --url http://sandbox.quigs.com",
)

# In run(), before client creation (~line 247):
if args.url:
    config.setdefault("target", {})["base_url"] = args.url
base_url = config["target"]["base_url"]
```

**Note:** `--target` already exists but sets the target **type** (app/ai/wordpress/generic), not the URL. The new `--url` flag sets the target **URL**. These are complementary.

---

#### Feature 2: WordPress Scan Profile (`--profile wordpress`)

**What:** A `--profile` flag that selects a predefined set of attack categories relevant to a platform, auto-configuring target type and relevant attack categories.

**Example Usage:**
```bash
# Run all WordPress-relevant scans
python -m redteam.runner --profile wordpress --url https://sandbox.quigs.com

# Equivalent to:
python -m redteam.runner --target wordpress --category wordpress --url https://sandbox.quigs.com
# ...but also includes web category attacks relevant to WP
```

**WordPress Profile Should Include:**
- Authenticated XSS (reflected + stored)
- SQL injection via query params
- AJAX endpoint auth bypass (`admin-ajax.php`)
- Nonce validation testing
- Capability escalation (`current_user_can` bypass)
- Unauthenticated REST API access (`/wp-json/`)
- File upload abuse
- Plugin/theme enumeration
- XMLRPC abuse
- User enumeration

**Existing Coverage:**
- `redteam/attacks/wordpress/` — plugin_audit, xmlrpc, user_enum, rest_api already exist
- `redteam/attacks/web/` — security_headers, cors, clickjacking apply to any target
- **Gaps:** No dedicated AJAX auth bypass, nonce validation, or capability escalation attacks yet

**Files to Modify:**

| File | Change |
|------|--------|
| `redteam/runner.py` | Add `--profile` flag. When `wordpress` profile selected: set `target_types = {"wordpress", "generic"}`, enable categories `wordpress` + `web`, auto-set WordPress config defaults. |
| `redteam/profiles/` | **New directory.** Create `wordpress.yaml`, `generic.yaml`, etc. defining which categories/attacks/config defaults each profile enables. |
| `redteam/runner.py` | Load profile YAML and merge into config before attack filtering (~line 231 `_filter_by_target()`). |

---

#### Feature 3: Static/Source Scan Mode (`--path`)

**What:** Point at a local directory for pattern-based PHP security analysis instead of scanning a live URL.

**Example Usage:**
```bash
# Static scan of a WordPress plugin source
python -m redteam.runner --category php-static \
  --path /var/www/html/wordpress/wp-content/plugins/cxq-membership

# Combined: static + live scan
python -m redteam.runner --profile wordpress \
  --url https://sandbox.quigs.com \
  --path /var/www/html/wordpress/wp-content/plugins/cxq-membership
```

**Existing Asset:**
Blue team already has a full PHP static analysis scanner at `blueteam/api/codebase_scanner.py` (`CodebaseSecurityScanner` class) with 7 pattern categories:
- SQL injection (CWE-89)
- XSS / unescaped output (CWE-79)
- Path traversal (CWE-22)
- Hardcoded credentials (CWE-798)
- Weak crypto — MD5/SHA1 (CWE-327)
- Unsafe file uploads (CWE-434)
- Unsafe deserialization (CWE-502)

**Strategy:** Wrap the blue team scanner as a red team attack module rather than reimplementing.

**Files to Modify:**

| File | Change |
|------|--------|
| `redteam/runner.py` | Add `--path` flag to `parse_args()`. When set, store as `config["target"]["source_path"]`. If `--path` is set without `--url`, skip HTTP client creation and run only static attacks. |
| `redteam/attacks/static/php_source_audit.py` | **New file.** A red team `Attack` subclass with `target_types={"static"}` that wraps `blueteam.api.codebase_scanner.CodebaseSecurityScanner`. Reads `self._config["target"]["source_path"]`, runs the scanner, converts results to `AttackResult` objects. |
| `redteam/base.py` | Add `"static"` to the valid target types documentation (no code change needed — target_types is a free-form set). |
| `redteam/runner.py` | In `run()`, handle the case where target includes `"static"` — skip client creation, pass `None` as client to static attacks, or create a no-op client. |

---

#### Feature 4: Auth Config Override (Runtime Credentials)

**What:** Pass WordPress admin credentials at runtime so authenticated endpoint scanning works without baking test accounts into `config.yaml`.

**Example Usage:**
```bash
# Pass credentials at runtime
python -m redteam.runner --profile wordpress \
  --url https://sandbox.quigs.com \
  --wp-user admin --wp-pass 'S3cur3P@ss!'

# Or via environment variables (already partially supported)
WP_ADMIN_USER=admin WP_ADMIN_PASS='S3cur3P@ss!' python -m redteam.runner --target wordpress
```

**Current State:**
Config already supports `${ENV_VAR}` substitution (`shared/config.py` handles this). Auth test users are defined in `config.yaml` under `auth.test_users.wp_admin` with env var placeholders `${WP_ADMIN_USER}` / `${WP_ADMIN_PASS}`.

**Files to Modify:**

| File | Change |
|------|--------|
| `redteam/runner.py` | Add `--wp-user` and `--wp-pass` flags. When set, override `config["auth"]["test_users"]["wp_admin"]["username"]` and `password` before client creation. |

**Implementation:**
```python
# In parse_args():
parser.add_argument("--wp-user", type=str, default=None, help="WordPress admin username")
parser.add_argument("--wp-pass", type=str, default=None, help="WordPress admin password")

# In run(), before client creation:
if args.wp_user:
    config.setdefault("auth", {}).setdefault("test_users", {}).setdefault("wp_admin", {})["username"] = args.wp_user
if args.wp_pass:
    config["auth"]["test_users"]["wp_admin"]["password"] = args.wp_pass
```

---

#### Acceptance Criteria

- [ ] `--url http://sandbox.quigs.com` overrides `base_url` without touching config files
- [ ] `--url` works alongside `--target`, `--category`, `--origin-ip`
- [ ] `--profile wordpress` runs all WordPress-relevant attacks across categories
- [ ] `--path /some/dir` runs static PHP analysis via red team attack framework
- [ ] `--path` can combine with `--url` for static + live scanning in one run
- [ ] `--wp-user` / `--wp-pass` override config credentials at runtime
- [ ] Existing `config.yaml`-only workflow is unaffected (no regression)
- [ ] `cyberguardian/cli.py` subparser updated with all new flags for parity

---
