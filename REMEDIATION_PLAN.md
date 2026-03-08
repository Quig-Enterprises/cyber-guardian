# Eqmon Security Remediation Plan

**Generated:** 2026-03-08
**Source:** Blue Team Codebase Scanner
**Target:** /var/www/html/eqmon

---

## Executive Summary

The blue team codebase scanner identified two categories of security findings in the eqmon application:

1. **CRITICAL — File Upload Vulnerabilities (3 issues):** Upload endpoints in `/var/www/html/eqmon/api/` lack sufficient validation, creating risk of malicious file upload, web shell deployment, and server compromise. These require immediate remediation.

2. **HIGH — innerHTML XSS Vulnerabilities (49+ issues):** JavaScript files in `/var/www/html/eqmon/js/` use `innerHTML` assignments that may expose the application to Cross-Site Scripting attacks. A triage-first approach is recommended, as many findings are likely false positives, but any `innerHTML` involving user-controlled data must be fixed.

---

## Phase 1: CRITICAL — File Upload Security (Priority: Immediate)

### Current State

The scanner identified 3 file upload endpoints in `/var/www/html/eqmon/api/` (e.g., `upload.php` or similar handlers) that exhibit one or more of the following deficiencies:

- No server-side MIME type validation (relying on file extension or client-supplied Content-Type only)
- No enforced file size limits
- No malware scanning integration
- Uploads potentially stored within the document root, enabling direct HTTP access to uploaded files
- Filenames may not be randomized, enabling predictable path enumeration

An attacker exploiting these issues could upload a PHP web shell and execute arbitrary commands on the server.

### Remediation Steps

1. **Audit all upload endpoints.** Identify every `$_FILES` reference in `/var/www/html/eqmon/api/`. Confirm the 3 flagged files and check for any additional handlers.

2. **Implement server-side MIME type validation.** Use PHP's `finfo` extension to inspect actual file content rather than trusting the extension or `$_FILES['type']`.

3. **Enforce file size limits.** Set hard limits in both `php.ini` (`upload_max_filesize`, `post_max_size`) and within application code to reject oversized uploads before processing.

4. **Integrate ClamAV malware scanning.** Scan every uploaded file before it is accepted. Reject and delete files that fail scanning.

5. **Move upload storage outside the document root.** Files must not be accessible directly via HTTP. Store them in a directory outside `/var/www/html/` (e.g., `/var/uploads/eqmon/`).

6. **Randomize stored filenames.** Never use the original client-supplied filename on disk. Generate a UUID or random hex string as the stored filename, and record the mapping in the database.

7. **Serve downloads through a controlled PHP endpoint.** Issue proper `Content-Disposition: attachment` headers and validate access permissions before streaming files to users.

8. **Create a shared validation library.** Extract upload validation logic into `/var/www/html/eqmon/lib/upload-validator.php` so all upload endpoints use a single, audited code path.

9. **Update `php.ini` settings.** Confirm `file_uploads = On` is intentional, set appropriate `upload_max_filesize` and `post_max_size`, and ensure error display is off in production.

10. **Add an `.htaccess` deny rule** to the upload storage directory (if any legacy storage paths remain inside the webroot) as a defense-in-depth measure.

### Implementation Guide

#### Shared Upload Validator (`lib/upload-validator.php`)

```php
<?php
/**
 * Eqmon Upload Validator
 * Centralizes all file upload security checks.
 */

class UploadValidator {

    // Allowed MIME types (add to this list as needed)
    private static array $ALLOWED_MIME_TYPES = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'application/pdf',
    ];

    // Max file size in bytes (10 MB)
    private static int $MAX_FILE_SIZE = 10 * 1024 * 1024;

    // Storage path outside document root
    private static string $UPLOAD_DIR = '/var/uploads/eqmon/';

    /**
     * Validate and store an uploaded file.
     *
     * @param array $file  Entry from $_FILES
     * @return array       ['success' => bool, 'stored_name' => string|null, 'error' => string|null]
     */
    public static function process(array $file): array {
        // 1. Check for upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return self::fail('Upload error code: ' . $file['error']);
        }

        // 2. Enforce size limit
        if ($file['size'] > self::$MAX_FILE_SIZE) {
            return self::fail('File exceeds maximum allowed size.');
        }

        // 3. Server-side MIME detection via finfo (ignores client Content-Type)
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($file['tmp_name']);
        if (!in_array($mimeType, self::$ALLOWED_MIME_TYPES, true)) {
            return self::fail('File type not permitted: ' . $mimeType);
        }

        // 4. ClamAV scan via clamd socket (preferred) or clamscan CLI
        $scanResult = self::clamavScan($file['tmp_name']);
        if ($scanResult !== 'OK') {
            @unlink($file['tmp_name']);
            return self::fail('File failed malware scan: ' . $scanResult);
        }

        // 5. Generate randomized storage filename
        $extension = self::safeExtension($mimeType);
        $storedName = bin2hex(random_bytes(16)) . '.' . $extension;
        $destPath = self::$UPLOAD_DIR . $storedName;

        // 6. Ensure upload directory exists
        if (!is_dir(self::$UPLOAD_DIR)) {
            mkdir(self::$UPLOAD_DIR, 0750, true);
        }

        // 7. Move file out of temp location
        if (!move_uploaded_file($file['tmp_name'], $destPath)) {
            return self::fail('Failed to store uploaded file.');
        }

        return ['success' => true, 'stored_name' => $storedName, 'error' => null];
    }

    /**
     * Scan a file with ClamAV.
     * Preferred: clamd socket via clamdscan (lower overhead).
     * Fallback: clamscan CLI.
     *
     * Uses escapeshellarg() to prevent injection; no user-supplied data
     * reaches the shell — only the server-generated temp file path does.
     */
    private static function clamavScan(string $filePath): string {
        // Try clamd socket first (faster for sustained load)
        if (file_exists('/var/run/clamav/clamd.ctl')) {
            $output = shell_exec('clamdscan --no-summary ' . escapeshellarg($filePath) . ' 2>&1');
        } else {
            // Fall back to clamscan CLI
            $output = shell_exec('clamscan --no-summary ' . escapeshellarg($filePath) . ' 2>&1');
        }

        // Output ends with "... OK" on clean files, "... FOUND" on infection
        if ($output !== null && str_contains($output, ': OK')) {
            return 'OK';
        }
        return trim($output ?? 'Scan unavailable');
    }

    /**
     * Map a MIME type to a safe file extension.
     */
    private static function safeExtension(string $mimeType): string {
        $map = [
            'image/jpeg'       => 'jpg',
            'image/png'        => 'png',
            'image/gif'        => 'gif',
            'image/webp'       => 'webp',
            'application/pdf'  => 'pdf',
        ];
        return $map[$mimeType] ?? 'bin';
    }

    private static function fail(string $message): array {
        return ['success' => false, 'stored_name' => null, 'error' => $message];
    }
}
```

#### Secure Download Endpoint (`api/download.php`)

```php
<?php
require_once __DIR__ . '/../lib/upload-validator.php';

session_start();
if (empty($_SESSION['user_id'])) {
    http_response_code(403);
    exit('Forbidden');
}

$storedName = $_GET['file'] ?? '';

// Whitelist: only hex-generated names with safe extension (matches our pattern)
if (!preg_match('/^[a-f0-9]{32}\.[a-z]{2,4}$/', $storedName)) {
    http_response_code(400);
    exit('Invalid filename');
}

$filePath = '/var/uploads/eqmon/' . $storedName;
if (!file_exists($filePath)) {
    http_response_code(404);
    exit('Not found');
}

$finfo = new finfo(FILEINFO_MIME_TYPE);
$mimeType = $finfo->file($filePath);

header('Content-Type: ' . $mimeType);
header('Content-Disposition: attachment; filename="download.' . pathinfo($storedName, PATHINFO_EXTENSION) . '"');
header('Content-Length: ' . filesize($filePath));
header('X-Content-Type-Options: nosniff');
readfile($filePath);
exit;
```

#### Updated Upload Endpoint (example `api/upload.php`)

```php
<?php
require_once __DIR__ . '/../lib/upload-validator.php';

session_start();
if (empty($_SESSION['user_id'])) {
    http_response_code(403);
    echo json_encode(['error' => 'Forbidden']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_FILES['file'])) {
    http_response_code(400);
    echo json_encode(['error' => 'No file uploaded']);
    exit;
}

$result = UploadValidator::process($_FILES['file']);

if (!$result['success']) {
    http_response_code(422);
    echo json_encode(['error' => $result['error']]);
    exit;
}

// Store $result['stored_name'] in your database linked to the user/record
// $db->saveUpload($_SESSION['user_id'], $result['stored_name']);

echo json_encode(['success' => true, 'file_id' => $result['stored_name']]);
```

### Verification

1. **Functional test — rejected file types:**
   ```bash
   curl -F "file=@shell.php" https://your-eqmon-host/api/upload.php
   # Expected: HTTP 422, {"error":"File type not permitted: ..."}
   ```

2. **Functional test — oversized file:**
   ```bash
   dd if=/dev/urandom of=/tmp/bigfile.jpg bs=1M count=20
   curl -F "file=@/tmp/bigfile.jpg" https://your-eqmon-host/api/upload.php
   # Expected: HTTP 422, size error
   ```

3. **Confirm storage location:**
   ```bash
   ls /var/uploads/eqmon/    # Files appear here
   ls /var/www/html/eqmon/   # No uploaded files here
   ```

4. **Confirm ClamAV is active:**
   ```bash
   systemctl status clamav-daemon
   clamscan --version
   ```

5. **Confirm no direct HTTP access to upload directory:**
   Attempt to access `/uploads/` or any path under the webroot that previously stored files — all should return 403 or 404.

---

## Phase 2: HIGH — innerHTML XSS Prevention (Priority: Short-term)

### Current State

The scanner identified 49+ usages of `innerHTML` across JavaScript files in `/var/www/html/eqmon/js/`. While `innerHTML` is not inherently dangerous when the inserted content is fully server-controlled or static, any usage that incorporates user-supplied data (URL parameters, form inputs, API responses containing user data) creates a reflected or stored XSS vector.

The bulk of findings are likely false positives (template strings building UI from trusted data), but each must be triaged individually. Even one genuine case is exploitable.

### Triage Approach

Categorize each `innerHTML` usage into one of three buckets:

**Bucket A — False Positive (No action required)**
- Content is entirely static string literals
- Content comes from hardcoded server configuration with no user influence
- Example: `el.innerHTML = '<span class="icon">...</span>'`

**Bucket B — Low Risk (Document and monitor)**
- Content comes from server API responses where the server already HTML-encodes output
- No path for user-controlled data to reach this code
- Example: `el.innerHTML = data.label` where `label` is a trusted enum from the backend
- Action: Add a comment noting the trust assumption; flag for re-review if the data source changes

**Bucket C — Genuine Risk (Fix immediately)**
- Content includes `location.search`, `location.hash`, `location.href`, or `URLSearchParams`
- Content includes form `input.value`, `textarea.value`, or similar DOM input sources
- Content includes data from third-party or user-facing APIs without sanitization
- Content uses `decodeURIComponent` on URL parameters
- Example: `el.innerHTML = 'Hello, ' + getParam('name')`

**Triage commands to find highest-risk patterns:**

```bash
# Find innerHTML combined with common user-input sources (Bucket C candidates)
grep -rn "innerHTML" /var/www/html/eqmon/js/ \
  | grep -E "location\.(search|hash|href)|URLSearchParams|input\.value|decodeURI"

# Find all innerHTML assignments for full manual review
grep -rn "\.innerHTML\s*=" /var/www/html/eqmon/js/ | sort
```

### Remediation Steps

1. **Run the triage commands** above and classify every finding into Bucket A, B, or C.

2. **Fix all Bucket C findings immediately** using the safe DOM patterns documented in the Implementation Guide below.

3. **Add DOMPurify as a fallback sanitizer** for cases where rich HTML must be rendered from semi-trusted sources. Load it from a local copy (not CDN) to avoid supply chain risk.

4. **Add a Content-Security-Policy (CSP) header** to the application. A restrictive CSP is the most effective defense-in-depth control for XSS. Start with report-only mode to identify breakage before enforcing.

5. **Review Bucket B findings** with the backend team to confirm server-side encoding guarantees. Document conclusions in code comments.

6. **Establish a linting rule** to flag new `innerHTML` assignments in CI. Use ESLint with the `no-unsanitized/property` rule from `eslint-plugin-no-unsanitized`.

7. **Test all fixed components** to confirm UI rendering is correct after switching to safe DOM methods.

### Implementation Guide

#### Pattern 1: Replace text-only innerHTML with textContent

```javascript
// BEFORE (vulnerable if content is user-controlled)
element.innerHTML = userInput;

// AFTER (safe — renders as plain text, never as HTML)
element.textContent = userInput;
```

#### Pattern 2: Replace innerHTML template building with DOM methods

```javascript
// BEFORE (XSS risk if any variable is user-controlled)
container.innerHTML = `
  <div class="item">
    <span class="name">${item.name}</span>
    <span class="value">${item.value}</span>
  </div>
`;

// AFTER (safe DOM construction)
function createItemElement(item) {
    const div = document.createElement('div');
    div.className = 'item';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'name';
    nameSpan.textContent = item.name;  // textContent auto-escapes

    const valueSpan = document.createElement('span');
    valueSpan.className = 'value';
    valueSpan.textContent = item.value;

    div.appendChild(nameSpan);
    div.appendChild(valueSpan);
    return div;
}

container.innerHTML = '';
container.appendChild(createItemElement(item));
```

#### Pattern 3: Safe helper for rendering lists

```javascript
// Utility: safely render a list of items without innerHTML
function renderList(container, items, renderItem) {
    container.innerHTML = '';
    const fragment = document.createDocumentFragment();
    items.forEach(item => fragment.appendChild(renderItem(item)));
    container.appendChild(fragment);
}

// Usage
renderList(listEl, apiData, (row) => {
    const li = document.createElement('li');
    li.textContent = row.label;
    return li;
});
```

#### Pattern 4: DOMPurify for cases requiring HTML rendering

Use only when rich HTML must be rendered from semi-trusted sources (e.g., a CMS field with formatting).

```html
<!-- Load DOMPurify from local copy, not CDN -->
<script src="/js/vendor/purify.min.js"></script>
```

```javascript
// BEFORE
element.innerHTML = serverHtml;

// AFTER — sanitize before rendering
element.innerHTML = DOMPurify.sanitize(serverHtml, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'title'],
    ALLOW_DATA_ATTR: false,
});
```

Download: https://github.com/cure53/DOMPurify/releases

#### Pattern 5: Handling URL parameters safely

```javascript
// BEFORE (reflected XSS via URL parameter)
const params = new URLSearchParams(location.search);
document.getElementById('greeting').innerHTML = 'Hello, ' + params.get('name');

// AFTER (safe)
const params = new URLSearchParams(location.search);
document.getElementById('greeting').textContent = 'Hello, ' + (params.get('name') || 'Guest');
```

#### Content-Security-Policy Header (nginx)

Add to the eqmon nginx server block or to `/etc/nginx/snippets/security-headers.conf`:

```nginx
# Start with report-only to detect violations without breaking functionality
add_header Content-Security-Policy-Report-Only
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; report-uri /api/csp-report.php"
  always;
```

Once violations are resolved, switch to enforcing:

```nginx
add_header Content-Security-Policy
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
  always;
```

#### ESLint Rule (if a build process exists)

```bash
npm install --save-dev eslint-plugin-no-unsanitized
```

`.eslintrc.json`:
```json
{
  "plugins": ["no-unsanitized"],
  "rules": {
    "no-unsanitized/property": "error",
    "no-unsanitized/method": "error"
  }
}
```

### Verification

1. **Re-run triage grep after fixes — confirm zero Bucket C findings:**
   ```bash
   grep -rn "\.innerHTML\s*=" /var/www/html/eqmon/js/ \
     | grep -E "location\.(search|hash|href)|URLSearchParams|input\.value|decodeURI"
   # Expected: no output
   ```

2. **Manual XSS probe on all fixed endpoints:**
   - Append `?name=<script>alert(1)</script>` to any URL that previously reflected `location.search` into `innerHTML`
   - Confirm no alert fires and the string renders as escaped text

3. **CSP violation report review:**
   - After enabling report-only CSP, monitor `/api/csp-report.php` logs for 48 hours
   - Each violation indicates a source that needs to be allowlisted or fixed

4. **Browser DevTools check:**
   - Load key pages and inspect the console for CSP violation messages
   - Confirm no `innerHTML` warnings appear in ESLint output

---

## Timeline

| Phase | Task | Target Completion |
|-------|------|-------------------|
| Phase 1 | Audit all `$_FILES` references, confirm 3 upload handlers | Day 1 |
| Phase 1 | Deploy `lib/upload-validator.php` with MIME + size validation | Day 2 |
| Phase 1 | Install and configure ClamAV (`apt install clamav clamav-daemon`) | Day 2 |
| Phase 1 | Integrate ClamAV scanning into upload validator | Day 3 |
| Phase 1 | Move upload storage outside document root | Day 3 |
| Phase 1 | Implement secure download endpoint with Content-Disposition | Day 4 |
| Phase 1 | Verify and close — test all upload endpoints | Day 5 |
| Phase 2 | Run triage grep, classify all 49+ innerHTML findings | Day 6 |
| Phase 2 | Fix all Bucket C (genuine risk) innerHTML usages | Days 7–10 |
| Phase 2 | Deploy DOMPurify for remaining semi-trusted HTML rendering | Day 10 |
| Phase 2 | Enable CSP in report-only mode | Day 11 |
| Phase 2 | Review CSP reports, resolve violations | Days 12–14 |
| Phase 2 | Switch CSP to enforcing mode | Day 15 |
| Phase 2 | Add ESLint no-unsanitized rule to development workflow | Day 15 |
| Both | Final security review and sign-off | Day 16 |

---

## References

### File Upload Security
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- CWE-434: Unrestricted Upload of File with Dangerous Type: https://cwe.mitre.org/data/definitions/434.html
- ClamAV Documentation: https://docs.clamav.net/

### XSS and innerHTML
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP DOM-based XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- CWE-79: Improper Neutralization of Input During Web Page Generation: https://cwe.mitre.org/data/definitions/79.html
- DOMPurify: https://github.com/cure53/DOMPurify
- MDN innerHTML security considerations: https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations

### Content Security Policy
- OWASP CSP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- MDN CSP Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- CSP Evaluator (Google): https://csp-evaluator.withgoogle.com/
