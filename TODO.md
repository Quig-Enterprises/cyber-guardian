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
