"""DNSSEC validation attack module.

Checks whether a domain has DNSSEC properly configured, including
RRSIG records and DS records at the parent zone.

Evaluation:
- No RRSIG records in dig output -> VULNERABLE
- DS record missing at parent zone -> PARTIAL
- Both RRSIG and DS present -> DEFENDED
"""

import asyncio
import shutil
import time
from urllib.parse import urlparse

from redteam.base import Attack, AttackResult, Severity, Status


class DNSSECAttack(Attack):
    """Check DNSSEC configuration for the target domain."""

    name = "dns.dnssec"
    category = "dns"
    severity = Severity.MEDIUM
    description = "DNSSEC validation checks — RRSIG records and DS record at parent zone"
    target_types = {"app", "wordpress", "generic"}

    def _get_hostname(self) -> str:
        """Extract hostname - prefer FQDN config for DNS/TLS accuracy."""
        fqdn = self._config.get("target", {}).get("fqdn", "")
        if fqdn:
            return fqdn
        base_url = self._config.get("target", {}).get("base_url", "")
        parsed = urlparse(base_url)
        return parsed.hostname or ""

    async def _run_dig(self, *args: str) -> tuple[int, str, str]:
        """Run dig with the given arguments and return (returncode, stdout, stderr)."""
        dig = shutil.which("dig")
        if not dig:
            return -1, "", "dig not found"
        proc = await asyncio.create_subprocess_exec(
            dig,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    async def execute(self, client) -> list[AttackResult]:
        results = []

        dig = shutil.which("dig")
        if not dig:
            results.append(self._make_result(
                variant="dnssec_enabled",
                status=Status.ERROR,
                evidence="dig binary not found in PATH",
                details="dig is not installed. Install with: apt install dnsutils",
            ))
            return results

        hostname = self._get_hostname()
        if not hostname:
            results.append(self._make_result(
                variant="dnssec_enabled",
                status=Status.ERROR,
                evidence="Could not determine target hostname from config",
                details="Set target.base_url in configuration to enable DNS checks",
            ))
            return results

        # Variant 1: dnssec_enabled — check for RRSIG records
        results.append(await self._check_dnssec_enabled(hostname))

        # Variant 2: ds_record — check for DS record at parent zone
        results.append(await self._check_ds_record(hostname))

        return results

    async def _check_dnssec_enabled(self, hostname: str) -> AttackResult:
        """Check if DNSSEC is enabled by looking for RRSIG records."""
        start = time.monotonic()
        returncode, stdout, stderr = await self._run_dig("+dnssec", hostname, "A")
        duration = (time.monotonic() - start) * 1000

        if returncode == -1:
            return self._make_result(
                variant="dnssec_enabled",
                status=Status.ERROR,
                evidence=stderr,
                details="dig not available",
                duration_ms=duration,
            )

        output_lower = stdout.lower()
        has_rrsig = "rrsig" in output_lower
        # AD flag in the header means the resolver validated DNSSEC
        flags_section = output_lower.split("flags:")[1].split(";")[0] if "flags:" in output_lower else ""
        has_ad_flag = "ad" in flags_section

        request = {"command": f"dig +dnssec {hostname} A"}
        response = {"has_rrsig": has_rrsig, "has_ad_flag": has_ad_flag, "output_preview": stdout[:500]}

        if has_rrsig:
            return self._make_result(
                variant="dnssec_enabled",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"RRSIG record found for {hostname}",
                details="DNSSEC is enabled — RRSIG records are present in the DNS response",
                request=request,
                response=response,
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="dnssec_enabled",
                status=Status.VULNERABLE,
                evidence=f"No RRSIG records found for {hostname}",
                details=(
                    "DNSSEC is not enabled for this domain. Without DNSSEC, DNS responses "
                    "can be forged (DNS spoofing/cache poisoning attacks)."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )

    async def _check_ds_record(self, hostname: str) -> AttackResult:
        """Check for DS record at the parent zone."""
        start = time.monotonic()
        returncode, stdout, stderr = await self._run_dig("DS", hostname)
        duration = (time.monotonic() - start) * 1000

        if returncode == -1:
            return self._make_result(
                variant="ds_record",
                status=Status.ERROR,
                evidence=stderr,
                details="dig not available",
                duration_ms=duration,
            )

        output_lower = stdout.lower()
        has_ds = " ds " in output_lower or "\tds\t" in output_lower
        nxdomain = "nxdomain" in output_lower

        request = {"command": f"dig DS {hostname}"}
        response = {"has_ds": has_ds, "nxdomain": nxdomain, "output_preview": stdout[:500]}

        if has_ds:
            return self._make_result(
                variant="ds_record",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"DS record found at parent zone for {hostname}",
                details="DS record is present at the parent zone — the DNSSEC chain of trust is established",
                request=request,
                response=response,
                duration_ms=duration,
            )
        elif nxdomain:
            return self._make_result(
                variant="ds_record",
                status=Status.VULNERABLE,
                evidence=f"NXDOMAIN response for DS query on {hostname}",
                details=(
                    "No DS record found — DNSSEC chain of trust is broken. "
                    "Even if RRSIG records exist, validation will fail without the DS record at the parent zone."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="ds_record",
                status=Status.PARTIAL,
                evidence=f"DS record not found for {hostname} (no NXDOMAIN, but DS absent)",
                details=(
                    "DS record was not returned. The domain may have DNSSEC partially configured "
                    "or the parent zone has not been updated with the DS record."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )
