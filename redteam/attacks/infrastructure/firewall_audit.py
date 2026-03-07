"""Firewall rules review -- checks iptables/nftables/ufw configuration.

Evaluation:
- No firewall active -> VULNERABLE
- Default INPUT/FORWARD policy is ACCEPT -> VULNERABLE
- Overly permissive rules (0.0.0.0/0 on sensitive ports) -> VULNERABLE
- Unexpected ports open -> PARTIAL
- Proper restrictive rules in place -> DEFENDED
"""

import asyncio
import logging
import shutil

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Ports that should never have unrestricted 0.0.0.0/0 ACCEPT rules
SENSITIVE_PORTS = {
    "22": "SSH",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "11211": "Memcached",
    "2379": "etcd",
    "9200": "Elasticsearch",
    "5601": "Kibana",
    "8080": "HTTP-Alt",
    "8443": "HTTPS-Alt",
    "9090": "Prometheus",
    "3000": "Grafana/Dev",
}


class FirewallAuditAttack(Attack):
    """Audit firewall rules for security weaknesses."""

    name = "infrastructure.firewall_audit"
    category = "infrastructure"
    severity = Severity.HIGH
    description = "Review firewall rules for insecure configurations"
    target_types = {"app", "wordpress", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all firewall audit variants."""
        results: list[AttackResult] = []

        results.append(await self._check_firewall_active())
        results.append(await self._check_default_policy())
        results.append(await self._check_open_ports())
        results.append(await self._check_unrestricted_input())

        return results

    async def _run_cmd(self, *args: str) -> tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)."""
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return (
            proc.returncode,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )

    async def _detect_firewall(self) -> tuple[str, str]:
        """Detect which firewall is active. Returns (type, raw_output).

        type is one of: 'ufw', 'nftables', 'iptables', 'none'.
        """
        # Check UFW first (most common on Ubuntu/Debian)
        if shutil.which("ufw"):
            rc, out, _ = await self._run_cmd("sudo", "ufw", "status")
            if rc == 0 and "Status: active" in out:
                return "ufw", out

        # Check nftables
        if shutil.which("nft"):
            rc, out, _ = await self._run_cmd("sudo", "nft", "list", "ruleset")
            if rc == 0 and out.strip():
                return "nftables", out

        # Check iptables
        if shutil.which("iptables"):
            rc, out, _ = await self._run_cmd("sudo", "iptables", "-L", "-n")
            if rc == 0:
                return "iptables", out

        return "none", ""

    async def _check_firewall_active(self) -> AttackResult:
        """Check if any firewall (iptables/nftables/ufw) is active."""
        fw_type, raw_output = await self._detect_firewall()

        if fw_type == "none":
            return self._make_result(
                variant="firewall_active",
                status=Status.VULNERABLE,
                severity=Severity.CRITICAL,
                evidence="No active firewall detected (checked ufw, nftables, iptables)",
                details=(
                    "No firewall is active on this system. All ports are exposed to "
                    "the network. Enable a firewall immediately. On Ubuntu/Debian: "
                    "'sudo ufw enable'. Note: if this is an AWS instance, security "
                    "groups provide network-level filtering but host-based firewall "
                    "is still recommended for defense in depth."
                ),
                request={"checked": ["ufw", "nftables", "iptables"]},
                response={"firewall": "none"},
            )

        return self._make_result(
            variant="firewall_active",
            status=Status.DEFENDED,
            evidence="Firewall active: " + fw_type,
            details=fw_type + " firewall is active and running.",
            request={"checked": ["ufw", "nftables", "iptables"]},
            response={"firewall": fw_type, "output_preview": raw_output[:500]},
        )

    async def _check_default_policy(self) -> AttackResult:
        """Check default INPUT/FORWARD policy (should be DROP/REJECT)."""
        fw_type, raw_output = await self._detect_firewall()

        if fw_type == "none":
            return self._make_result(
                variant="default_policy",
                status=Status.SKIPPED,
                evidence="No firewall detected; cannot check default policy",
                details="Enable a firewall first, then re-run this check.",
            )

        input_policy = "unknown"
        forward_policy = "unknown"

        if fw_type == "ufw":
            if "Default: deny (incoming)" in raw_output or "Default: reject (incoming)" in raw_output:
                input_policy = "deny/reject"
            elif "Default: allow (incoming)" in raw_output:
                input_policy = "allow"
            if "Default: deny (routed)" in raw_output or "Default: reject (routed)" in raw_output:
                forward_policy = "deny/reject"
            elif "Default: allow (routed)" in raw_output:
                forward_policy = "allow"

        elif fw_type == "iptables":
            for line in raw_output.splitlines():
                line = line.strip()
                if line.startswith("Chain INPUT") and "(policy " in line:
                    policy = line.split("(policy ")[1].split(")")[0].strip()
                    input_policy = policy
                elif line.startswith("Chain FORWARD") and "(policy " in line:
                    policy = line.split("(policy ")[1].split(")")[0].strip()
                    forward_policy = policy

        elif fw_type == "nftables":
            for line in raw_output.splitlines():
                lower = line.strip().lower()
                if "chain input" in lower or ("type filter" in lower and "input" in lower):
                    if "policy drop" in lower:
                        input_policy = "drop"
                    elif "policy accept" in lower:
                        input_policy = "accept"
                if "chain forward" in lower or ("type filter" in lower and "forward" in lower):
                    if "policy drop" in lower:
                        forward_policy = "drop"
                    elif "policy accept" in lower:
                        forward_policy = "accept"

        insecure_policies: list[str] = []
        if input_policy.lower() in ("accept", "allow"):
            insecure_policies.append("INPUT policy: " + input_policy)
        if forward_policy.lower() in ("accept", "allow"):
            insecure_policies.append("FORWARD policy: " + forward_policy)

        if insecure_policies:
            return self._make_result(
                variant="default_policy",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="; ".join(insecure_policies),
                details=(
                    "Default firewall policy is too permissive. "
                    "The default policy for INPUT and FORWARD chains should be DROP or REJECT "
                    "to deny all traffic not explicitly allowed.\n"
                    + "\n".join("  - " + p for p in insecure_policies)
                ),
                request={"firewall": fw_type},
                response={"input_policy": input_policy, "forward_policy": forward_policy},
            )

        return self._make_result(
            variant="default_policy",
            status=Status.DEFENDED,
            evidence="INPUT policy: " + input_policy + ", FORWARD policy: " + forward_policy,
            details="Default firewall policies are restrictive (DROP/REJECT).",
            request={"firewall": fw_type},
            response={"input_policy": input_policy, "forward_policy": forward_policy},
        )

    async def _check_open_ports(self) -> AttackResult:
        """List ports with ACCEPT rules and flag unexpected ones."""
        fw_type, raw_output = await self._detect_firewall()

        if fw_type == "none":
            return self._make_result(
                variant="open_ports",
                status=Status.SKIPPED,
                evidence="No firewall detected; cannot enumerate open port rules",
                details="Enable a firewall first, then re-run this check.",
            )

        accepted_ports: list[str] = []

        if fw_type == "ufw":
            for line in raw_output.splitlines():
                line = line.strip()
                if "ALLOW" in line and line and not line.startswith("--"):
                    accepted_ports.append(line)

        elif fw_type == "iptables":
            for line in raw_output.splitlines():
                line = line.strip()
                if "ACCEPT" in line and ("dpt:" in line or "dports" in line):
                    accepted_ports.append(line)

        elif fw_type == "nftables":
            for line in raw_output.splitlines():
                line = line.strip()
                if "accept" in line.lower() and ("dport" in line or "port" in line):
                    accepted_ports.append(line)

        if not accepted_ports:
            return self._make_result(
                variant="open_ports",
                status=Status.DEFENDED,
                evidence="No explicit port ACCEPT rules found",
                details="No ports are explicitly allowed through the firewall.",
                request={"firewall": fw_type},
                response={"accepted_rules": []},
            )

        flagged: list[str] = []
        for rule in accepted_ports:
            for port, service in SENSITIVE_PORTS.items():
                if port in rule:
                    flagged.append("Port " + port + " (" + service + "): " + rule.strip())

        if flagged:
            return self._make_result(
                variant="open_ports",
                status=Status.PARTIAL,
                severity=Severity.MEDIUM,
                evidence=str(len(accepted_ports)) + " ACCEPT rule(s), " + str(len(flagged)) + " on sensitive ports",
                details=(
                    "Found " + str(len(accepted_ports)) + " port ACCEPT rule(s). "
                    "Sensitive ports with ACCEPT rules:\n"
                    + "\n".join("  - " + f for f in flagged[:15])
                    + "\nReview whether all of these ports need to be accessible."
                ),
                request={"firewall": fw_type},
                response={"total_rules": len(accepted_ports), "flagged": flagged[:15]},
            )

        return self._make_result(
            variant="open_ports",
            status=Status.DEFENDED,
            evidence=str(len(accepted_ports)) + " ACCEPT rule(s), none on sensitive ports",
            details="Found " + str(len(accepted_ports)) + " port ACCEPT rule(s); none match known sensitive ports.",
            request={"firewall": fw_type},
            response={"total_rules": len(accepted_ports), "rules": accepted_ports[:20]},
        )

    async def _check_unrestricted_input(self) -> AttackResult:
        """Check for overly permissive rules (0.0.0.0/0 ACCEPT on sensitive ports)."""
        fw_type, raw_output = await self._detect_firewall()

        if fw_type == "none":
            return self._make_result(
                variant="unrestricted_input",
                status=Status.SKIPPED,
                evidence="No firewall detected",
                details="Enable a firewall first, then re-run this check.",
            )

        unrestricted: list[str] = []

        if fw_type == "ufw":
            for line in raw_output.splitlines():
                line = line.strip()
                if "ALLOW" in line and "Anywhere" in line:
                    for port, service in SENSITIVE_PORTS.items():
                        if port in line:
                            unrestricted.append(
                                "Port " + port + " (" + service + ") allowed from Anywhere: " + line
                            )

        elif fw_type == "iptables":
            for line in raw_output.splitlines():
                line = line.strip()
                if "ACCEPT" not in line:
                    continue
                if "0.0.0.0/0" in line:
                    for port, service in SENSITIVE_PORTS.items():
                        if ("dpt:" + port) in line or ("dports " + port) in line:
                            unrestricted.append(
                                "Port " + port + " (" + service + ") open to 0.0.0.0/0: " + line
                            )

        elif fw_type == "nftables":
            for line in raw_output.splitlines():
                stripped = line.strip().lower()
                if "accept" in stripped and "0.0.0.0/0" in stripped:
                    for port, service in SENSITIVE_PORTS.items():
                        if ("dport " + port) in stripped:
                            unrestricted.append(
                                "Port " + port + " (" + service + ") open to 0.0.0.0/0: " + line.strip()
                            )

        if unrestricted:
            return self._make_result(
                variant="unrestricted_input",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=str(len(unrestricted)) + " unrestricted rule(s) on sensitive ports",
                details=(
                    "Sensitive ports are accessible from any source IP (0.0.0.0/0). "
                    "Restrict these rules to specific IP ranges:\n"
                    + "\n".join("  - " + u for u in unrestricted[:15])
                ),
                request={"firewall": fw_type},
                response={"unrestricted_rules": unrestricted[:15]},
            )

        return self._make_result(
            variant="unrestricted_input",
            status=Status.DEFENDED,
            evidence="No unrestricted ACCEPT rules on sensitive ports",
            details=(
                "No overly permissive firewall rules were found for sensitive ports. "
                "Note: for AWS instances, also review Security Group rules."
            ),
            request={"firewall": fw_type},
            response={"unrestricted_rules": []},
        )
