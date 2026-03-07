"""Security Group Audit - checks for unrestricted ingress, default SG rules, and wide port ranges."""

import asyncio
import json
import shutil

from redteam.base import Attack, AttackResult, Severity, Status


# Sensitive ports that should never be open to 0.0.0.0/0 or ::/0
SENSITIVE_PORTS = {22, 3306, 5432, 6379, 27017, 11211, 9200}
ANY_IPV4 = "0.0.0.0/0"
ANY_IPV6 = "::/0"


class SecurityGroupsAttack(Attack):
    name = "cloud.security_groups"
    category = "cloud"
    severity = Severity.HIGH
    description = "Audit EC2 security groups for unrestricted ingress, default SG rules, and wide port ranges"
    target_types = {"app", "wordpress", "generic"}

    async def _run_aws(self, *args) -> tuple[int, str, str]:
        """Run an aws CLI command and return (returncode, stdout, stderr)."""
        aws = shutil.which("aws")
        proc = await asyncio.create_subprocess_exec(
            aws, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    async def execute(self, client) -> list[AttackResult]:
        results = []

        aws = shutil.which("aws")
        if not aws:
            skip_msg = (
                "aws CLI not found in PATH. "
                "Install the AWS CLI to enable security group auditing: https://aws.amazon.com/cli/"
            )
            return [
                self._make_result(variant="unrestricted_ingress", status=Status.SKIPPED,
                                  evidence="aws CLI not found", details=skip_msg),
                self._make_result(variant="default_sg_rules", status=Status.SKIPPED,
                                  evidence="aws CLI not found", details=skip_msg),
                self._make_result(variant="wide_port_ranges", status=Status.SKIPPED,
                                  evidence="aws CLI not found", details=skip_msg),
            ]

        rc, stdout, stderr = await self._run_aws(
            "ec2", "describe-security-groups", "--output", "json"
        )
        if rc != 0:
            skip_detail = (
                "Unable to describe EC2 security groups. Ensure AWS credentials are configured "
                "and the ec2:DescribeSecurityGroups permission is granted.\n"
                f"Error: {stderr[:300]}"
            )
            return [
                self._make_result(variant="unrestricted_ingress", status=Status.SKIPPED,
                                  evidence=stderr[:500], details=skip_detail),
                self._make_result(variant="default_sg_rules", status=Status.SKIPPED,
                                  evidence=stderr[:500], details=skip_detail),
                self._make_result(variant="wide_port_ranges", status=Status.SKIPPED,
                                  evidence=stderr[:500], details=skip_detail),
            ]

        try:
            sg_data = json.loads(stdout)
        except json.JSONDecodeError:
            return [self._make_result(
                variant="unrestricted_ingress",
                status=Status.ERROR,
                evidence=stdout[:300],
                details="Failed to parse aws ec2 describe-security-groups JSON output.",
            )]

        all_groups = sg_data.get("SecurityGroups", [])
        throttle = self._get_throttle("cloud.security_groups")
        max_groups = throttle.get("max_groups", 50)
        groups = all_groups[:max_groups]

        # --- Variant 1: unrestricted_ingress ---
        open_sensitive = []
        for sg in groups:
            sg_id = sg.get("GroupId", "?")
            sg_name = sg.get("GroupName", "?")
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                protocol = perm.get("IpProtocol", "-1")

                # Determine which sensitive ports this rule covers
                if protocol == "-1":
                    # All traffic
                    covered_ports = SENSITIVE_PORTS
                else:
                    covered_ports = {
                        p for p in SENSITIVE_PORTS
                        if from_port <= p <= to_port
                    }

                if not covered_ports:
                    continue

                # Check for open CIDR ranges
                open_cidrs = []
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == ANY_IPV4:
                        open_cidrs.append(ANY_IPV4)
                for ip_range in perm.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == ANY_IPV6:
                        open_cidrs.append(ANY_IPV6)

                if open_cidrs:
                    ports_str = ", ".join(str(p) for p in sorted(covered_ports))
                    cidrs_str = ", ".join(open_cidrs)
                    open_sensitive.append(
                        f"{sg_id} ({sg_name}): ports [{ports_str}] open to {cidrs_str}"
                    )

        if open_sensitive:
            results.append(self._make_result(
                variant="unrestricted_ingress",
                status=Status.VULNERABLE,
                severity=Severity.CRITICAL,
                evidence="\n".join(open_sensitive[:20]),
                details=(
                    f"{len(open_sensitive)} security group rule(s) expose sensitive ports to the internet. "
                    "Restrict ingress to known IP ranges or use VPN/bastion host access patterns."
                ),
                request={"command": "aws ec2 describe-security-groups", "groups_checked": len(groups)},
                response={"vulnerable_rules": len(open_sensitive), "total_groups": len(all_groups)},
            ))
        else:
            results.append(self._make_result(
                variant="unrestricted_ingress",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"No sensitive ports exposed to 0.0.0.0/0 or ::/0 across {len(groups)} security groups.",
                details=f"Checked {len(groups)} of {len(all_groups)} total security groups.",
                request={"command": "aws ec2 describe-security-groups", "groups_checked": len(groups)},
                response={"vulnerable_rules": 0, "total_groups": len(all_groups)},
            ))

        # --- Variant 2: default_sg_rules ---
        # Per CIS AWS Benchmark, the default security group should have zero ingress/egress rules
        default_sgs_with_rules = []
        for sg in groups:
            if sg.get("GroupName") == "default":
                sg_id = sg.get("GroupId", "?")
                ingress = sg.get("IpPermissions", [])
                egress = sg.get("IpPermissionsEgress", [])
                # Default egress allows all traffic (1 rule) which is the AWS default — flag only if ingress rules exist
                # or if egress has more than the standard allow-all rule
                ingress_count = len(ingress)
                # Egress: AWS adds a default allow-all rule; flag if there are any restrictive egress overrides
                # or if ingress has any rules at all
                if ingress_count > 0:
                    default_sgs_with_rules.append(
                        f"{sg_id} (default): {ingress_count} ingress rule(s), {len(egress)} egress rule(s)"
                    )

        if default_sgs_with_rules:
            results.append(self._make_result(
                variant="default_sg_rules",
                status=Status.VULNERABLE,
                severity=Severity.MEDIUM,
                evidence="\n".join(default_sgs_with_rules),
                details=(
                    f"{len(default_sgs_with_rules)} default security group(s) have ingress rules configured. "
                    "CIS AWS Benchmark recommends the default security group restrict all traffic. "
                    "Resources should use purpose-built security groups instead."
                ),
                request={"command": "aws ec2 describe-security-groups", "filter": "GroupName=default"},
                response={"default_sgs_with_rules": len(default_sgs_with_rules)},
            ))
        else:
            results.append(self._make_result(
                variant="default_sg_rules",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence="Default security group(s) have no ingress rules (CIS compliant).",
                details="Default security groups restrict all inbound traffic as recommended by CIS AWS Benchmark.",
                request={"command": "aws ec2 describe-security-groups", "filter": "GroupName=default"},
                response={"default_sgs_with_rules": 0},
            ))

        # --- Variant 3: wide_port_ranges ---
        wide_range_rules = []
        for sg in groups:
            sg_id = sg.get("GroupId", "?")
            sg_name = sg.get("GroupName", "?")
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                protocol = perm.get("IpProtocol", "-1")

                # All-traffic rule (protocol -1) or explicit 0-65535
                is_all_traffic = protocol == "-1"
                is_wide_range = (
                    from_port is not None and to_port is not None
                    and from_port == 0 and to_port == 65535
                )

                if not (is_all_traffic or is_wide_range):
                    continue

                # Only flag if there are any source CIDRs (not SG references)
                has_cidr = bool(perm.get("IpRanges") or perm.get("Ipv6Ranges"))
                if has_cidr:
                    port_desc = "all traffic" if is_all_traffic else "ports 0-65535"
                    wide_range_rules.append(
                        f"{sg_id} ({sg_name}): {port_desc} open via CIDR"
                    )

        if wide_range_rules:
            results.append(self._make_result(
                variant="wide_port_ranges",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="\n".join(wide_range_rules[:20]),
                details=(
                    f"{len(wide_range_rules)} security group rule(s) allow all ports (0-65535) or all traffic. "
                    "Restrict rules to the minimum required ports and sources."
                ),
                request={"command": "aws ec2 describe-security-groups", "groups_checked": len(groups)},
                response={"wide_rules": len(wide_range_rules), "total_groups": len(all_groups)},
            ))
        else:
            results.append(self._make_result(
                variant="wide_port_ranges",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"No all-port rules found across {len(groups)} security groups.",
                details=f"Checked {len(groups)} of {len(all_groups)} total security groups.",
                request={"command": "aws ec2 describe-security-groups", "groups_checked": len(groups)},
                response={"wide_rules": 0, "total_groups": len(all_groups)},
            ))

        return results
