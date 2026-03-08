"""Email authentication DNS record checks: SPF, DKIM, DMARC.

Evaluates the target domain's email authentication posture by querying
DNS TXT records for SPF, DKIM selectors, and DMARC policy.

Evaluation:
- SPF missing -> VULNERABLE
- SPF present with ~all or ?all (soft fail / neutral) -> PARTIAL
- SPF present with -all (hard fail) -> DEFENDED
- No DKIM selectors found -> VULNERABLE
- At least one DKIM selector found -> DEFENDED
- DMARC missing -> VULNERABLE
- DMARC p=none -> PARTIAL
- DMARC p=quarantine or p=reject -> DEFENDED
"""

import asyncio
import shutil
import time
from urllib.parse import urlparse

from redteam.base import Attack, AttackResult, Severity, Status


DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "mail",
    "k1",
]


class EmailAuthAttack(Attack):
    """SPF, DKIM, and DMARC email authentication checks."""

    name = "dns.email_auth"
    category = "dns"
    severity = Severity.HIGH
    description = "SPF/DKIM/DMARC email authentication DNS record validation"
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
        """Run dig and return (returncode, stdout, stderr)."""
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
                variant="spf",
                status=Status.ERROR,
                evidence="dig binary not found in PATH",
                details="dig is not installed. Install with: apt install dnsutils",
            ))
            return results

        hostname = self._get_hostname()
        if not hostname:
            results.append(self._make_result(
                variant="spf",
                status=Status.ERROR,
                evidence="Could not determine target hostname from config",
                details="Set target.base_url in configuration to enable DNS checks",
            ))
            return results

        results.append(await self._check_spf(hostname))
        results.append(await self._check_dkim(hostname))
        results.append(await self._check_dmarc(hostname))

        return results

    async def _check_spf(self, hostname: str) -> AttackResult:
        """Query TXT records for SPF and evaluate the policy qualifier."""
        start = time.monotonic()
        returncode, stdout, stderr = await self._run_dig("TXT", hostname)
        duration = (time.monotonic() - start) * 1000

        if returncode == -1:
            return self._make_result(
                variant="spf",
                status=Status.ERROR,
                evidence=stderr,
                details="dig not available",
                duration_ms=duration,
            )

        request = {"command": f"dig TXT {hostname}"}

        # Extract SPF record from ANSWER SECTION
        spf_record = None
        in_answer = False
        for line in stdout.splitlines():
            if "ANSWER SECTION" in line:
                in_answer = True
                continue
            if in_answer and line.startswith(";"):
                in_answer = False
            if in_answer and "v=spf1" in line.lower():
                spf_record = line.strip()
                break

        response = {"spf_record": spf_record, "output_preview": stdout[:600]}

        if not spf_record:
            return self._make_result(
                variant="spf",
                status=Status.VULNERABLE,
                evidence=f"No SPF record found for {hostname}",
                details=(
                    "No SPF TXT record exists. Without SPF, anyone can send email claiming "
                    "to be from this domain (email spoofing)."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )

        spf_lower = spf_record.lower()

        if "-all" in spf_lower:
            return self._make_result(
                variant="spf",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"SPF record with hard fail (-all): {spf_record}",
                details="SPF is configured with -all (hard fail) — unauthorized senders will be rejected",
                request=request,
                response=response,
                duration_ms=duration,
            )
        elif "~all" in spf_lower:
            return self._make_result(
                variant="spf",
                status=Status.PARTIAL,
                evidence=f"SPF record with soft fail (~all): {spf_record}",
                details=(
                    "SPF uses ~all (soft fail) — unauthorized senders are marked but not rejected. "
                    "Consider upgrading to -all for stronger protection."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )
        elif "?all" in spf_lower:
            return self._make_result(
                variant="spf",
                status=Status.PARTIAL,
                evidence=f"SPF record with neutral (?all): {spf_record}",
                details=(
                    "SPF uses ?all (neutral) — provides no real protection. "
                    "Upgrade to ~all or -all to enforce SPF policy."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="spf",
                status=Status.PARTIAL,
                evidence=f"SPF record without explicit all qualifier: {spf_record}",
                details=(
                    "SPF record exists but has no explicit 'all' mechanism. "
                    "Add -all or ~all to define behaviour for unauthorized senders."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )

    async def _check_dkim(self, hostname: str) -> AttackResult:
        """Check common DKIM selectors for a valid DKIM TXT record."""
        start = time.monotonic()
        found_selectors: list[str] = []
        missing_selectors: list[str] = []

        for selector in DKIM_SELECTORS:
            dkim_host = f"{selector}._domainkey.{hostname}"
            _, stdout, _ = await self._run_dig("TXT", dkim_host)
            has_dkim = "v=dkim1" in stdout.lower() or "p=" in stdout.lower()
            if has_dkim:
                found_selectors.append(selector)
            else:
                missing_selectors.append(selector)

        duration = (time.monotonic() - start) * 1000
        request = {
            "command": f"dig TXT <selector>._domainkey.{hostname}",
            "selectors_checked": DKIM_SELECTORS,
        }
        response = {
            "found_selectors": found_selectors,
            "missing_selectors": missing_selectors,
        }

        if found_selectors:
            return self._make_result(
                variant="dkim",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"DKIM records found for selectors: {', '.join(found_selectors)}",
                details=(
                    f"DKIM is configured for {hostname} with selector(s): {', '.join(found_selectors)}. "
                    "Email recipients can verify message authenticity."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="dkim",
                status=Status.VULNERABLE,
                evidence=f"No DKIM records found for any of the common selectors on {hostname}",
                details=(
                    f"No DKIM TXT records found at common selectors ({', '.join(DKIM_SELECTORS)}). "
                    "Without DKIM, recipients cannot verify that emails were sent by authorised servers "
                    "and email contents may be modified in transit."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )

    async def _check_dmarc(self, hostname: str) -> AttackResult:
        """Query DMARC TXT record and evaluate the policy."""
        start = time.monotonic()
        dmarc_host = f"_dmarc.{hostname}"
        returncode, stdout, stderr = await self._run_dig("TXT", dmarc_host)
        duration = (time.monotonic() - start) * 1000

        request = {"command": f"dig TXT {dmarc_host}"}

        if returncode == -1:
            return self._make_result(
                variant="dmarc",
                status=Status.ERROR,
                evidence=stderr,
                details="dig not available",
                duration_ms=duration,
            )

        dmarc_record = None
        in_answer = False
        for line in stdout.splitlines():
            if "ANSWER SECTION" in line:
                in_answer = True
                continue
            if in_answer and line.startswith(";"):
                in_answer = False
            if in_answer and "v=dmarc1" in line.lower():
                dmarc_record = line.strip()
                break

        response = {"dmarc_record": dmarc_record, "output_preview": stdout[:600]}

        if not dmarc_record:
            return self._make_result(
                variant="dmarc",
                status=Status.VULNERABLE,
                evidence=f"No DMARC record found at {dmarc_host}",
                details=(
                    "No DMARC record exists. Without DMARC, email receivers have no policy "
                    "guidance for handling SPF/DKIM failures, enabling phishing and email spoofing."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )

        # Parse p= policy value
        policy = None
        for part in dmarc_record.lower().split(";"):
            part = part.strip()
            if part.startswith("p="):
                policy = part[2:].strip().strip('"')
                break

        response["policy"] = policy

        if policy == "reject":
            return self._make_result(
                variant="dmarc",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"DMARC with p=reject: {dmarc_record}",
                details="DMARC policy is 'reject' — the strongest setting. Unauthenticated emails are rejected.",
                request=request,
                response=response,
                duration_ms=duration,
            )
        elif policy == "quarantine":
            return self._make_result(
                variant="dmarc",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"DMARC with p=quarantine: {dmarc_record}",
                details=(
                    "DMARC policy is 'quarantine' — unauthenticated emails are sent to spam. "
                    "Consider upgrading to p=reject for maximum protection."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )
        elif policy == "none":
            return self._make_result(
                variant="dmarc",
                status=Status.PARTIAL,
                evidence=f"DMARC with p=none (monitor only): {dmarc_record}",
                details=(
                    "DMARC policy is 'none' — report-only mode with no enforcement. "
                    "Unauthenticated emails are still delivered. Upgrade to p=quarantine or p=reject."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="dmarc",
                status=Status.PARTIAL,
                evidence=f"DMARC record found but policy is unclear (p={policy}): {dmarc_record}",
                details="DMARC record exists but could not determine a recognised policy value.",
                request=request,
                response=response,
                duration_ms=duration,
            )
