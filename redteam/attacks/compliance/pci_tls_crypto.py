"""PCI DSS 4.0 Requirement 4 — Transmission Cryptography.

Verifies that strong cryptography is used to protect PAN during
transmission over open, public networks.  Checks TLS version,
cipher suites, certificate validity, HSTS headers, and perfect
forward secrecy.
"""

import ssl
import socket
import datetime
from urllib.parse import urlparse

from redteam.base import Attack, AttackResult, Severity, Status


# Ciphers that must never appear in a PCI-compliant deployment.
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5",
                "RC2", "IDEA", "SEED", "CAMELLIA128"}

# Protocols that must be rejected.
REJECTED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


class PCITLSCryptoAttack(Attack):
    name = "compliance.pci_tls_crypto"
    category = "compliance"
    severity = Severity.HIGH
    description = "PCI DSS 4.0 Req 4 — Verify strong cryptography for PAN transmission"

    def _parse_host_port(self, endpoint: str) -> tuple[str, int]:
        """Extract host and port from an endpoint or base_url."""
        base = self._config.get("target", {}).get("base_url", "https://localhost")
        url = urlparse(base)
        host = url.hostname or "localhost"
        port = url.port or (443 if url.scheme == "https" else 80)
        return host, port

    def _connect_tls(self, host: str, port: int,
                     context: ssl.SSLContext | None = None,
                     timeout: float = 5.0) -> ssl.SSLSocket | None:
        """Open a TLS socket and return it, or None on failure."""
        if context is None:
            context = ssl.create_default_context()
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            return context.wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            return None

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []
        endpoints = self._get_test_endpoints()
        host, port = self._parse_host_port(endpoints[0] if endpoints else "/")

        # ----------------------------------------------------------------
        # 1. TLS version check — must be TLS 1.2 or higher
        # ----------------------------------------------------------------
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = self._connect_tls(host, port, ctx)
            if conn:
                version = conn.version()
                conn.close()
                if version in REJECTED_PROTOCOLS:
                    tls_status = Status.VULNERABLE
                    detail = (
                        f"Server negotiated {version} which is prohibited by PCI DSS 4.0. "
                        "Only TLS 1.2+ is permitted for PAN transmission."
                    )
                else:
                    tls_status = Status.DEFENDED
                    detail = f"Server negotiated {version} which meets PCI DSS 4.0 requirements."
                evidence = f"Negotiated protocol: {version}"
            else:
                tls_status = Status.ERROR
                detail = "Could not establish TLS connection to target."
                evidence = f"Host: {host}:{port}, connection failed"
        except Exception as exc:
            tls_status = Status.ERROR
            detail = f"TLS version check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="tls_version_check",
            status=tls_status,
            severity=Severity.CRITICAL,
            evidence=evidence,
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 2. Cipher suite check — reject weak ciphers
        # ----------------------------------------------------------------
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = self._connect_tls(host, port, ctx)
            if conn:
                cipher_info = conn.cipher()  # (name, protocol, bits)
                conn.close()
                cipher_name = cipher_info[0] if cipher_info else "UNKNOWN"
                bits = cipher_info[2] if cipher_info else 0
                weak_found = [w for w in WEAK_CIPHERS
                              if w.upper() in cipher_name.upper()]
                if weak_found:
                    cipher_status = Status.VULNERABLE
                    detail = (
                        f"Negotiated cipher '{cipher_name}' contains weak component(s): "
                        f"{weak_found}. PCI DSS requires strong cryptography."
                    )
                elif bits < 128:
                    cipher_status = Status.VULNERABLE
                    detail = (
                        f"Negotiated cipher '{cipher_name}' uses only {bits}-bit keys. "
                        "PCI DSS requires minimum 128-bit key strength."
                    )
                else:
                    cipher_status = Status.DEFENDED
                    detail = (
                        f"Negotiated cipher '{cipher_name}' ({bits}-bit) "
                        "meets PCI DSS strength requirements."
                    )
                evidence = f"Cipher: {cipher_info}"
            else:
                cipher_status = Status.ERROR
                detail = "Could not establish TLS connection for cipher check."
                evidence = f"Host: {host}:{port}"
        except Exception as exc:
            cipher_status = Status.ERROR
            detail = f"Cipher suite check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="cipher_suite_check",
            status=cipher_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 3. Certificate validity — flag certs expiring within 30 days
        # ----------------------------------------------------------------
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            pem = ssl.get_server_certificate((host, port), timeout=5)
            # Parse the not-after date from the PEM certificate
            der = ssl.PEM_cert_to_DER_cert(pem)
            # Use ssl to decode
            x509 = ssl.DER_cert_to_PEM_cert(der)
            # Re-wrap to get parsed info via a temporary context
            check_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            check_ctx.check_hostname = False
            check_ctx.verify_mode = ssl.CERT_NONE
            conn = self._connect_tls(host, port, check_ctx)
            if conn:
                cert = conn.getpeercert(binary_form=False)
                conn.close()
                if cert and "notAfter" in cert:
                    not_after_str = cert["notAfter"]
                    # Format: 'Mar 15 12:00:00 2026 GMT'
                    not_after = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    )
                    days_left = (not_after - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        cert_status = Status.VULNERABLE
                        detail = (
                            f"Certificate EXPIRED {abs(days_left)} days ago "
                            f"(notAfter: {not_after_str}). PCI DSS requires valid certificates."
                        )
                    elif days_left < 30:
                        cert_status = Status.PARTIAL
                        detail = (
                            f"Certificate expires in {days_left} days "
                            f"(notAfter: {not_after_str}). Renewal is urgent."
                        )
                    else:
                        cert_status = Status.DEFENDED
                        detail = (
                            f"Certificate valid for {days_left} more days "
                            f"(notAfter: {not_after_str})."
                        )
                    evidence = f"notAfter: {not_after_str}, days_left: {days_left}"
                else:
                    # Could not parse — self-signed or no peer cert info
                    cert_status = Status.PARTIAL
                    detail = (
                        "TLS connection succeeded but peer certificate details "
                        "not available (possibly self-signed without trust)."
                    )
                    evidence = "getpeercert returned no date fields"
            else:
                cert_status = Status.ERROR
                detail = "Could not connect to check certificate validity."
                evidence = f"Host: {host}:{port}"
        except Exception as exc:
            cert_status = Status.ERROR
            detail = f"Certificate validity check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="certificate_validity",
            status=cert_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 4. HSTS header — Strict-Transport-Security with max-age >= 1yr
        # ----------------------------------------------------------------
        hsts_findings: list[tuple[str, str | None]] = []
        for ep in endpoints:
            try:
                status_code, body, headers = await client.get(ep)
                hsts = None
                for h in headers if isinstance(headers, list) else [headers]:
                    h_str = str(h)
                    if "strict-transport-security" in h_str.lower():
                        hsts = h_str
                        break
                # Also check if headers is a dict
                if isinstance(headers, dict):
                    hsts = headers.get("Strict-Transport-Security",
                           headers.get("strict-transport-security"))
                hsts_findings.append((ep, hsts))
            except Exception:
                hsts_findings.append((ep, None))

        missing_hsts = [(ep, h) for ep, h in hsts_findings if not h]
        weak_hsts = []
        for ep, h in hsts_findings:
            if h:
                import re
                match = re.search(r"max-age=(\d+)", str(h), re.IGNORECASE)
                if match and int(match.group(1)) < 31536000:
                    weak_hsts.append((ep, h))

        if missing_hsts and not any(h for _, h in hsts_findings):
            hsts_status = Status.VULNERABLE
            detail = (
                f"No HSTS header found on any endpoint ({len(missing_hsts)} checked). "
                "PCI DSS requires HSTS to prevent protocol downgrade attacks."
            )
        elif missing_hsts:
            hsts_status = Status.PARTIAL
            detail = (
                f"HSTS missing on {len(missing_hsts)}/{len(hsts_findings)} endpoints: "
                f"{[ep for ep, _ in missing_hsts]}."
            )
        elif weak_hsts:
            hsts_status = Status.PARTIAL
            detail = (
                f"HSTS max-age below 1 year on {len(weak_hsts)} endpoint(s): "
                f"{[ep for ep, _ in weak_hsts]}."
            )
        else:
            hsts_status = Status.DEFENDED
            detail = f"HSTS configured correctly on all {len(hsts_findings)} endpoints."

        results.append(self._make_result(
            variant="hsts_header",
            status=hsts_status,
            severity=Severity.MEDIUM,
            evidence=f"HSTS findings: {hsts_findings}",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 5. Perfect Forward Secrecy — cipher must use ECDHE or DHE
        # ----------------------------------------------------------------
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = self._connect_tls(host, port, ctx)
            if conn:
                cipher_name = conn.cipher()[0] if conn.cipher() else ""
                conn.close()
                has_pfs = any(kex in cipher_name.upper()
                             for kex in ("ECDHE", "DHE", "X25519", "X448"))
                if has_pfs:
                    pfs_status = Status.DEFENDED
                    detail = (
                        f"Cipher '{cipher_name}' provides Perfect Forward Secrecy "
                        "via ephemeral key exchange."
                    )
                else:
                    pfs_status = Status.VULNERABLE
                    detail = (
                        f"Cipher '{cipher_name}' does NOT use ephemeral key exchange "
                        "(ECDHE/DHE). Compromise of server key would expose past traffic."
                    )
                evidence = f"Cipher: {cipher_name}, PFS: {has_pfs}"
            else:
                pfs_status = Status.ERROR
                detail = "Could not establish TLS connection for PFS check."
                evidence = f"Host: {host}:{port}"
        except Exception as exc:
            pfs_status = Status.ERROR
            detail = f"PFS check failed: {exc}"
            evidence = str(exc)

        results.append(self._make_result(
            variant="perfect_forward_secrecy",
            status=pfs_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
        ))

        return results
