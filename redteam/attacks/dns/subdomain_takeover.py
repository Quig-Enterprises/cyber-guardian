"""Subdomain takeover detection module.

Checks whether any CNAME records for the target domain point to hosts
that do not exist (dangling CNAMEs), which can be claimed by an attacker
on the referenced service to serve malicious content under the target domain.

Evaluation:
- CNAME target resolves to NXDOMAIN -> VULNERABLE (takeover possible)
- CNAME target resolves successfully -> DEFENDED
- No CNAME on subdomain -> DEFENDED (not applicable)

AWS mode:
- 200 ms delay between lookups
- Only checks top 5 subdomains instead of all
"""

import asyncio
import shutil
import time
from urllib.parse import urlparse

from redteam.base import Attack, AttackResult, Severity, Status


COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "dev",
    "staging",
    "api",
    "admin",
    "cdn",
    "blog",
]

# Services known to be susceptible to subdomain takeover
TAKEOVER_SUSCEPTIBLE_SERVICES = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    "azurewebsites.net": "Azure Web Apps",
    "cloudapp.net": "Azure Cloud App",
    "myshopify.com": "Shopify",
    "shopify.com": "Shopify",
    "readthedocs.io": "Read the Docs",
    "surge.sh": "Surge.sh",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "pages.dev": "Cloudflare Pages",
    "fastly.net": "Fastly",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "statuspage.io": "Statuspage",
    "ghost.io": "Ghost",
    "webflow.io": "Webflow",
    "squarespace.com": "Squarespace",
    "wix.com": "Wix",
}


def _identify_susceptible_service(cname_target: str) -> str | None:
    """Return the name of a takeover-susceptible service if cname_target matches."""
    cname_lower = cname_target.lower().rstrip(".")
    for domain_fragment, service_name in TAKEOVER_SUSCEPTIBLE_SERVICES.items():
        if cname_lower.endswith(domain_fragment) or domain_fragment in cname_lower:
            return service_name
    return None


class SubdomainTakeoverAttack(Attack):
    """Detect dangling CNAME records susceptible to subdomain takeover."""

    name = "dns.subdomain_takeover"
    category = "dns"
    severity = Severity.HIGH
    description = "Subdomain takeover detection via dangling CNAME records"
    target_types = {"app", "wordpress", "generic"}

    def _get_hostname(self) -> str:
        """Extract hostname - prefer FQDN config for DNS/TLS accuracy."""
        fqdn = self._config.get("target", {}).get("fqdn", "")
        if fqdn:
            return fqdn
        base_url = self._config.get("target", {}).get("base_url", "")
        parsed = urlparse(base_url)
        return parsed.hostname or ""

    async def _run_dig(self, record_type: str, host: str) -> tuple[int, str, str]:
        """Run dig for the given record type and host."""
        dig = shutil.which("dig")
        if not dig:
            return -1, "", "dig not found"
        proc = await asyncio.create_subprocess_exec(
            dig,
            record_type,
            host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    def _parse_cname_target(self, stdout: str) -> str | None:
        """Parse the CNAME target from dig output, or None if no CNAME found."""
        in_answer = False
        for line in stdout.splitlines():
            if "ANSWER SECTION" in line:
                in_answer = True
                continue
            if in_answer and line.startswith(";"):
                in_answer = False
            if in_answer:
                parts = line.split()
                # CNAME answer line: <name> <ttl> IN CNAME <target>
                if len(parts) >= 5 and parts[3].upper() == "CNAME":
                    return parts[4].rstrip(".")
        return None

    def _is_nxdomain(self, stdout: str) -> bool:
        """Return True if dig output indicates NXDOMAIN."""
        return "nxdomain" in stdout.lower()

    async def _check_cname_dangling(self, fqdn: str) -> tuple[bool, str | None, bool]:
        """
        Check if fqdn has a dangling CNAME.

        Returns: (has_cname, cname_target, is_dangling)
        """
        _, cname_stdout, _ = await self._run_dig("CNAME", fqdn)
        cname_target = self._parse_cname_target(cname_stdout)

        if cname_target is None:
            return False, None, False

        # CNAME exists — now check if the target resolves
        _, a_stdout, _ = await self._run_dig("A", cname_target)
        is_dangling = self._is_nxdomain(a_stdout)

        return True, cname_target, is_dangling

    async def execute(self, client) -> list[AttackResult]:
        results = []

        dig = shutil.which("dig")
        if not dig:
            results.append(self._make_result(
                variant="dangling_cname",
                status=Status.ERROR,
                evidence="dig binary not found in PATH",
                details="dig is not installed. Install with: apt install dnsutils",
            ))
            return results

        hostname = self._get_hostname()
        if not hostname:
            results.append(self._make_result(
                variant="dangling_cname",
                status=Status.ERROR,
                evidence="Could not determine target hostname from config",
                details="Set target.base_url in configuration to enable DNS checks",
            ))
            return results

        # Variant 1: dangling_cname — check the apex/primary hostname itself
        results.append(await self._check_dangling_cname_variant(hostname))

        # Variant 2: common_subdomains — check common subdomains
        results.append(await self._check_common_subdomains_variant(hostname))

        return results

    async def _check_dangling_cname_variant(self, hostname: str) -> AttackResult:
        """Check the primary hostname for a dangling CNAME."""
        start = time.monotonic()
        has_cname, cname_target, is_dangling = await self._check_cname_dangling(hostname)
        duration = (time.monotonic() - start) * 1000

        request = {"command": f"dig CNAME {hostname} && dig A <cname_target>"}
        response = {
            "has_cname": has_cname,
            "cname_target": cname_target,
            "is_dangling": is_dangling,
        }

        if not has_cname:
            return self._make_result(
                variant="dangling_cname",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"No CNAME record on {hostname}",
                details="The primary hostname does not use a CNAME record — no dangling CNAME risk here",
                request=request,
                response=response,
                duration_ms=duration,
            )

        susceptible_service = _identify_susceptible_service(cname_target or "")

        if is_dangling:
            service_note = (
                f" The target resolves to a {susceptible_service} endpoint which is "
                f"known to be susceptible to subdomain takeover."
                if susceptible_service
                else " Check whether the service provider allows claiming unclaimed hostnames."
            )
            return self._make_result(
                variant="dangling_cname",
                status=Status.VULNERABLE,
                evidence=f"Dangling CNAME: {hostname} -> {cname_target} (NXDOMAIN)",
                details=(
                    f"{hostname} has a CNAME pointing to {cname_target} which returns NXDOMAIN. "
                    f"An attacker could register {cname_target} on the referenced service and serve "
                    f"content under {hostname}.{service_note}"
                ),
                request=request,
                response={**response, "susceptible_service": susceptible_service},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="dangling_cname",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"CNAME {hostname} -> {cname_target} resolves correctly",
                details="CNAME target resolves — no dangling CNAME detected for primary hostname",
                request=request,
                response=response,
                duration_ms=duration,
            )

    async def _check_common_subdomains_variant(self, hostname: str) -> AttackResult:
        """Check common subdomains for dangling CNAMEs."""
        start = time.monotonic()
        aws_mode = self._is_aws_mode()

        # In AWS mode, throttle and limit scope
        subdomains_to_check = COMMON_SUBDOMAINS[:5] if aws_mode else COMMON_SUBDOMAINS

        vulnerable: list[dict] = []
        defended: list[str] = []
        no_cname: list[str] = []

        for subdomain in subdomains_to_check:
            fqdn = f"{subdomain}.{hostname}"

            if aws_mode:
                await asyncio.sleep(0.2)  # 200 ms throttle in AWS mode

            has_cname, cname_target, is_dangling = await self._check_cname_dangling(fqdn)

            if not has_cname:
                no_cname.append(fqdn)
            elif is_dangling:
                susceptible_service = _identify_susceptible_service(cname_target or "")
                vulnerable.append({
                    "fqdn": fqdn,
                    "cname_target": cname_target,
                    "susceptible_service": susceptible_service,
                })
            else:
                defended.append(fqdn)

        duration = (time.monotonic() - start) * 1000

        request = {
            "command": "dig CNAME <subdomain>.<domain> && dig A <cname_target>",
            "subdomains_checked": subdomains_to_check,
            "aws_mode": aws_mode,
        }
        response = {
            "vulnerable": vulnerable,
            "defended": defended,
            "no_cname": no_cname,
        }

        if vulnerable:
            vuln_summary = "; ".join(
                f"{v['fqdn']} -> {v['cname_target']}"
                + (f" [{v['susceptible_service']}]" if v['susceptible_service'] else "")
                for v in vulnerable
            )
            return self._make_result(
                variant="common_subdomains",
                status=Status.VULNERABLE,
                evidence=f"Dangling CNAMEs found: {vuln_summary}",
                details=(
                    f"Found {len(vulnerable)} subdomain(s) with dangling CNAMEs that may be "
                    f"susceptible to takeover: {vuln_summary}. "
                    "An attacker can register the unclaimed service hostname and serve arbitrary content "
                    "under your domain."
                ),
                request=request,
                response=response,
                duration_ms=duration,
            )
        elif defended:
            return self._make_result(
                variant="common_subdomains",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"All CNAME subdomains checked resolve correctly: {', '.join(defended)}",
                details="No dangling CNAMEs detected across common subdomains",
                request=request,
                response=response,
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="common_subdomains",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"No CNAME records found on common subdomains of {hostname}",
                details="None of the common subdomains use CNAME records — no subdomain takeover risk via CNAMEs",
                request=request,
                response=response,
                duration_ms=duration,
            )
