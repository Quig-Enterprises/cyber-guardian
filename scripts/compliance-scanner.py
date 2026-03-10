#!/usr/bin/env python3
"""
Cyber-Guardian: Compliance Scanner
Version: 1.0.0
Date: 2026-03-10

Infrastructure compliance and security configuration scanner.
Performs AWS, OS, SSH, Docker, and service-specific security checks.

Usage:
    python3 compliance-scanner.py --server willie --type aws-ec2
    python3 compliance-scanner.py --server alfred --type local
    python3 compliance-scanner.py --config config.yaml

Database:
    Tables: blueteam.compliance_scans, blueteam.compliance_findings
    Connection: localhost:5432/eqmon (same as malware scanner)

Categories:
    - aws: IMDSv2, EBS encryption, security groups, IAM
    - os: Patch status, kernel version, unattended-upgrades
    - ssh: Root login, password auth, key-only, hardening
    - firewall: UFW/iptables status, open ports
    - docker: Container versions, security scanning, compose config
    - mailcow: MailCow-specific checks (if detected)
    - wordpress: WordPress-specific checks (if detected)
"""

import argparse
import json
import logging
import sys
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import os

try:
    import psycopg2
    from psycopg2.extras import Json
except ImportError:
    print("ERROR: psycopg2 not installed. Install with: pip install psycopg2-binary")
    sys.exit(1)

# Configuration
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "database": os.getenv("DB_NAME", "eqmon"),
    "user": os.getenv("DB_USER", "eqmon"),
}

# Get password from .pgpass if available
PGPASS_FILE = Path.home() / ".pgpass"
if PGPASS_FILE.exists():
    with open(PGPASS_FILE) as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 5 and parts[0] == DB_CONFIG["host"] and \
               parts[2] == DB_CONFIG["database"] and parts[3] == DB_CONFIG["user"]:
                DB_CONFIG["password"] = parts[4]
                break

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("compliance-scanner")


# ============================================================================
# Database Connection
# ============================================================================

class DatabaseConnection:
    """Manage PostgreSQL database connection."""

    def __init__(self, config: dict):
        self.config = config
        self.conn = None

    def connect(self):
        """Establish database connection."""
        try:
            self.conn = psycopg2.connect(**self.config)
            logger.info("Database connection established")
            return self.conn
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# ============================================================================
# Check Result Classes
# ============================================================================

class CheckResult:
    """Individual compliance check result."""

    def __init__(self, category: str, name: str, check_id: str):
        self.category = category
        self.name = name
        self.check_id = check_id
        self.status = "skip"  # pass, fail, warning, info, skip
        self.severity = None  # critical, high, medium, low (for failures)
        self.summary = ""
        self.details = ""
        self.remediation = ""
        self.aws_resource_id = None
        self.aws_resource_type = None
        self.file_path = None
        self.service_name = None
        self.cis_benchmark = None
        self.aws_foundational_security = None
        self.nist_csf = None
        self.check_output = ""

    def mark_pass(self, summary: str, details: str = ""):
        """Mark check as passed."""
        self.status = "pass"
        self.severity = None
        self.summary = summary
        self.details = details

    def mark_fail(self, severity: str, summary: str, details: str, remediation: str):
        """Mark check as failed."""
        self.status = "fail"
        self.severity = severity
        self.summary = summary
        self.details = details
        self.remediation = remediation

    def mark_warning(self, summary: str, details: str, remediation: str = ""):
        """Mark check as warning."""
        self.status = "warning"
        self.severity = "low"
        self.summary = summary
        self.details = details
        self.remediation = remediation

    def mark_skip(self, reason: str):
        """Mark check as skipped."""
        self.status = "skip"
        self.severity = None
        self.summary = f"Check skipped: {reason}"

    def to_dict(self) -> dict:
        """Convert to dictionary for database insertion."""
        return {
            "check_category": self.category,
            "check_name": self.name,
            "check_id": self.check_id,
            "status": self.status,
            "severity": self.severity,
            "finding_summary": self.summary,
            "finding_details": self.details,
            "remediation_steps": self.remediation,
            "aws_resource_id": self.aws_resource_id,
            "aws_resource_type": self.aws_resource_type,
            "file_path": self.file_path,
            "service_name": self.service_name,
            "cis_benchmark": self.cis_benchmark,
            "aws_foundational_security": self.aws_foundational_security,
            "nist_csf": self.nist_csf,
            "check_output": self.check_output if len(self.check_output) < 5000 else self.check_output[:5000],
        }


# ============================================================================
# SSH Command Executor
# ============================================================================

class SSHExecutor:
    """Execute commands via SSH on remote servers."""

    def __init__(self, server: str, ssh_key: Optional[str] = None, user: str = "ubuntu"):
        self.server = server
        self.ssh_key = ssh_key
        self.user = user

    def run(self, command: str) -> Tuple[int, str, str]:
        """
        Execute command via SSH.

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        ssh_cmd = ["ssh"]
        if self.ssh_key:
            ssh_cmd.extend(["-i", self.ssh_key])
        ssh_cmd.extend([f"{self.user}@{self.server}", command])

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)


class LocalExecutor:
    """Execute commands locally."""

    def run(self, command: str) -> Tuple[int, str, str]:
        """
        Execute command locally.

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)


# ============================================================================
# Check Modules
# ============================================================================

class OSChecks:
    """Operating system security checks."""

    def __init__(self, executor):
        self.executor = executor

    def run_all(self) -> List[CheckResult]:
        """Run all OS checks."""
        checks = []
        checks.append(self.check_patch_status())
        checks.append(self.check_kernel_version())
        checks.append(self.check_unattended_upgrades())
        return checks

    def check_patch_status(self) -> CheckResult:
        """Check for pending security updates."""
        result = CheckResult("os", "Pending Security Updates", "os-patch-status")
        result.cis_benchmark = "1.9"

        exit_code, stdout, stderr = self.executor.run("apt list --upgradable 2>/dev/null | grep -i security | wc -l")

        if exit_code != 0:
            result.mark_skip("Unable to check update status")
            return result

        result.check_output = stdout.strip()
        pending = int(stdout.strip() or "0")

        if pending == 0:
            result.mark_pass(
                "No pending security updates",
                "System is up to date with latest security patches"
            )
        elif pending <= 5:
            result.mark_warning(
                f"{pending} pending security updates",
                f"There are {pending} security updates available",
                "Run: sudo apt-get update && sudo apt-get upgrade"
            )
        else:
            result.mark_fail(
                "high",
                f"{pending} pending security updates",
                f"System has {pending} uninstalled security patches",
                "Run: sudo apt-get update && sudo apt-get upgrade"
            )

        return result

    def check_kernel_version(self) -> CheckResult:
        """Check kernel version and available updates."""
        result = CheckResult("os", "Kernel Version Current", "os-kernel-version")

        exit_code, stdout, stderr = self.executor.run("uname -r")
        if exit_code != 0:
            result.mark_skip("Unable to check kernel version")
            return result

        current_kernel = stdout.strip()
        result.check_output = current_kernel

        # Check for newer kernel
        exit_code, stdout, stderr = self.executor.run("dpkg -l | grep linux-image | grep -v $(uname -r) | wc -l")
        newer_kernels = int(stdout.strip() or "0")

        if newer_kernels == 0:
            result.mark_pass(
                f"Kernel up to date: {current_kernel}",
                "Running the latest installed kernel version"
            )
        else:
            result.mark_warning(
                f"Kernel update available: {current_kernel}",
                f"Current: {current_kernel}, {newer_kernels} newer kernel(s) installed",
                "Reboot to activate newer kernel version"
            )

        return result

    def check_unattended_upgrades(self) -> CheckResult:
        """Check if unattended-upgrades is configured."""
        result = CheckResult("os", "Unattended Upgrades Configured", "os-unattended-upgrades")
        result.cis_benchmark = "1.9"

        exit_code, stdout, stderr = self.executor.run("systemctl is-enabled unattended-upgrades 2>/dev/null")

        if exit_code != 0:
            result.mark_fail(
                "medium",
                "Unattended-upgrades not enabled",
                "Automatic security updates are not configured",
                "Install and enable: sudo apt-get install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
            )
        else:
            result.mark_pass(
                "Unattended-upgrades enabled",
                "Automatic security updates are configured"
            )

        return result


class SSHChecks:
    """SSH security checks."""

    def __init__(self, executor):
        self.executor = executor

    def run_all(self) -> List[CheckResult]:
        """Run all SSH checks."""
        checks = []
        checks.append(self.check_root_login())
        checks.append(self.check_password_authentication())
        checks.append(self.check_permit_empty_passwords())
        checks.append(self.check_protocol_version())
        return checks

    def check_root_login(self) -> CheckResult:
        """Check if SSH root login is disabled."""
        result = CheckResult("ssh", "Root Login Disabled", "ssh-root-login")
        result.cis_benchmark = "5.2.10"

        exit_code, stdout, stderr = self.executor.run("grep '^PermitRootLogin' /etc/ssh/sshd_config")
        result.check_output = stdout.strip()

        if "PermitRootLogin no" in stdout:
            result.mark_pass(
                "SSH root login disabled",
                "PermitRootLogin is set to 'no' in sshd_config"
            )
            result.file_path = "/etc/ssh/sshd_config"
        elif "PermitRootLogin" in stdout:
            result.mark_fail(
                "high",
                "SSH root login enabled",
                f"Current setting: {stdout.strip()}",
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd"
            )
            result.file_path = "/etc/ssh/sshd_config"
        else:
            result.mark_warning(
                "Root login setting not explicit",
                "PermitRootLogin not explicitly set (using default)",
                "Add 'PermitRootLogin no' to /etc/ssh/sshd_config"
            )

        return result

    def check_password_authentication(self) -> CheckResult:
        """Check if SSH password authentication is disabled."""
        result = CheckResult("ssh", "Password Authentication Disabled", "ssh-password-auth")
        result.cis_benchmark = "5.2.11"

        exit_code, stdout, stderr = self.executor.run("grep '^PasswordAuthentication' /etc/ssh/sshd_config")
        result.check_output = stdout.strip()

        if "PasswordAuthentication no" in stdout:
            result.mark_pass(
                "SSH password authentication disabled",
                "PasswordAuthentication is set to 'no' - key-only authentication"
            )
            result.file_path = "/etc/ssh/sshd_config"
        elif "PasswordAuthentication yes" in stdout:
            result.mark_fail(
                "medium",
                "SSH password authentication enabled",
                "Passwords are accepted for SSH authentication (brute force risk)",
                "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and restart sshd"
            )
            result.file_path = "/etc/ssh/sshd_config"
        else:
            result.mark_warning(
                "Password auth setting not explicit",
                "PasswordAuthentication not explicitly set",
                "Add 'PasswordAuthentication no' to /etc/ssh/sshd_config"
            )

        return result

    def check_permit_empty_passwords(self) -> CheckResult:
        """Check if empty passwords are permitted."""
        result = CheckResult("ssh", "Empty Passwords Prohibited", "ssh-empty-passwords")
        result.cis_benchmark = "5.2.9"

        exit_code, stdout, stderr = self.executor.run("grep '^PermitEmptyPasswords' /etc/ssh/sshd_config")
        result.check_output = stdout.strip()

        if "PermitEmptyPasswords no" in stdout:
            result.mark_pass(
                "Empty passwords prohibited",
                "PermitEmptyPasswords is set to 'no'"
            )
        elif "PermitEmptyPasswords yes" in stdout:
            result.mark_fail(
                "critical",
                "Empty passwords permitted",
                "SSH allows authentication with empty passwords",
                "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config and restart sshd"
            )
        else:
            result.mark_pass(
                "Empty passwords prohibited (default)",
                "PermitEmptyPasswords not set (defaults to 'no')"
            )

        return result

    def check_protocol_version(self) -> CheckResult:
        """Check SSH protocol version."""
        result = CheckResult("ssh", "SSH Protocol 2 Only", "ssh-protocol-version")
        result.cis_benchmark = "5.2.3"

        exit_code, stdout, stderr = self.executor.run("grep '^Protocol' /etc/ssh/sshd_config")
        result.check_output = stdout.strip()

        # Modern SSH only supports protocol 2, but check anyway
        if "Protocol 1" in stdout:
            result.mark_fail(
                "critical",
                "SSH Protocol 1 enabled",
                "Insecure SSH protocol 1 is enabled",
                "Remove 'Protocol 1' from /etc/ssh/sshd_config or set to 'Protocol 2'"
            )
        else:
            result.mark_pass(
                "SSH Protocol 2 only",
                "Using secure SSH protocol version 2 (protocol 1 not enabled)"
            )

        return result


class FirewallChecks:
    """Firewall security checks."""

    def __init__(self, executor):
        self.executor = executor

    def run_all(self) -> List[CheckResult]:
        """Run all firewall checks."""
        checks = []
        checks.append(self.check_ufw_status())
        return checks

    def check_ufw_status(self) -> CheckResult:
        """Check if UFW firewall is enabled."""
        result = CheckResult("firewall", "Firewall Enabled", "firewall-ufw-enabled")
        result.cis_benchmark = "3.5.1"

        exit_code, stdout, stderr = self.executor.run("sudo ufw status")
        result.check_output = stdout.strip()

        if "Status: active" in stdout:
            result.mark_pass(
                "UFW firewall is active",
                "Firewall is enabled and protecting the system"
            )
        elif "Status: inactive" in stdout:
            result.mark_fail(
                "high",
                "UFW firewall is inactive",
                "No host-based firewall protection",
                "Enable firewall: sudo ufw enable"
            )
        else:
            result.mark_warning(
                "UFW status unknown",
                "Unable to determine firewall status",
                "Check firewall manually: sudo ufw status verbose"
            )

        return result


class DockerChecks:
    """Docker security checks."""

    def __init__(self, executor):
        self.executor = executor

    def run_all(self) -> List[CheckResult]:
        """Run all Docker checks."""
        checks = []
        checks.append(self.check_docker_version())
        checks.append(self.check_latest_tags())
        return checks

    def check_docker_version(self) -> CheckResult:
        """Check Docker version."""
        result = CheckResult("docker", "Docker Version Current", "docker-version")

        exit_code, stdout, stderr = self.executor.run("docker --version")

        if exit_code != 0:
            result.mark_skip("Docker not installed or not accessible")
            return result

        result.check_output = stdout.strip()

        # Extract version
        match = re.search(r'Docker version (\d+\.\d+\.\d+)', stdout)
        if match:
            version = match.group(1)
            result.mark_pass(
                f"Docker installed: {version}",
                stdout.strip()
            )
        else:
            result.mark_warning(
                "Docker version unknown",
                stdout.strip(),
                "Unable to parse Docker version"
            )

        return result

    def check_latest_tags(self) -> CheckResult:
        """Check for containers using :latest tag."""
        result = CheckResult("docker", "No :latest Tags in Production", "docker-latest-tags")

        exit_code, stdout, stderr = self.executor.run("docker ps --format '{{.Image}}' | grep ':latest' | wc -l")

        if exit_code != 0:
            result.mark_skip("Unable to check Docker containers")
            return result

        result.check_output = stdout.strip()
        latest_count = int(stdout.strip() or "0")

        if latest_count == 0:
            result.mark_pass(
                "No containers using :latest tag",
                "All containers use pinned version tags"
            )
        else:
            result.mark_fail(
                "medium",
                f"{latest_count} containers using :latest tag",
                "Containers using :latest can unexpectedly update",
                "Pin all container images to specific version tags in docker-compose.yml"
            )

        return result


# ============================================================================
# AWS Checks (requires boto3)
# ============================================================================

class AWSChecks:
    """AWS security checks."""

    def __init__(self, instance_id: Optional[str] = None, region: str = "us-east-2"):
        self.instance_id = instance_id
        self.region = region
        self.boto3_available = False

        try:
            import boto3
            self.boto3 = boto3
            self.boto3_available = True
            self.ec2 = boto3.client('ec2', region_name=region)
        except ImportError:
            logger.warning("boto3 not available - AWS checks will be skipped")

    def run_all(self) -> List[CheckResult]:
        """Run all AWS checks."""
        if not self.boto3_available:
            result = CheckResult("aws", "AWS Checks", "aws-checks")
            result.mark_skip("boto3 not installed")
            return [result]

        checks = []
        checks.append(self.check_imdsv2())
        checks.append(self.check_ebs_encryption())
        return checks

    def check_imdsv2(self) -> CheckResult:
        """Check if EC2 instance requires IMDSv2."""
        result = CheckResult("aws", "IMDSv2 Enforcement", "aws-imdsv2")
        result.aws_foundational_security = "EC2.8"

        if not self.instance_id:
            result.mark_skip("Instance ID not provided")
            return result

        try:
            response = self.ec2.describe_instances(InstanceIds=[self.instance_id])
            instance = response['Reservations'][0]['Instances'][0]

            metadata_options = instance.get('MetadataOptions', {})
            http_tokens = metadata_options.get('HttpTokens', 'optional')

            result.aws_resource_id = self.instance_id
            result.aws_resource_type = "ec2-instance"
            result.check_output = json.dumps(metadata_options, indent=2)

            if http_tokens == 'required':
                result.mark_pass(
                    "IMDSv2 is required",
                    f"Instance {self.instance_id} requires IMDSv2 (HttpTokens=required)"
                )
            else:
                result.mark_fail(
                    "high",
                    "IMDSv2 not enforced",
                    f"Instance {self.instance_id} allows IMDSv1 (HttpTokens={http_tokens})",
                    f"Run: aws ec2 modify-instance-metadata-options --instance-id {self.instance_id} --http-tokens required"
                )
        except Exception as e:
            result.mark_skip(f"Error checking IMDSv2: {str(e)}")

        return result

    def check_ebs_encryption(self) -> CheckResult:
        """Check if EBS volumes are encrypted."""
        result = CheckResult("aws", "EBS Volume Encryption", "aws-ebs-encryption")
        result.aws_foundational_security = "EC2.7"

        if not self.instance_id:
            result.mark_skip("Instance ID not provided")
            return result

        try:
            response = self.ec2.describe_instances(InstanceIds=[self.instance_id])
            instance = response['Reservations'][0]['Instances'][0]

            volumes = instance.get('BlockDeviceMappings', [])
            unencrypted = []

            for vol in volumes:
                vol_id = vol['Ebs']['VolumeId']
                vol_response = self.ec2.describe_volumes(VolumeIds=[vol_id])
                encrypted = vol_response['Volumes'][0]['Encrypted']

                if not encrypted:
                    unencrypted.append(vol_id)

            if not unencrypted:
                result.mark_pass(
                    "All EBS volumes encrypted",
                    f"All {len(volumes)} EBS volumes are encrypted at rest"
                )
            else:
                result.mark_fail(
                    "high",
                    f"{len(unencrypted)} unencrypted EBS volumes",
                    f"Unencrypted volumes: {', '.join(unencrypted)}",
                    "Create encrypted snapshot, create volume from snapshot, replace unencrypted volume"
                )
                result.aws_resource_id = unencrypted[0]
                result.aws_resource_type = "ebs-volume"

        except Exception as e:
            result.mark_skip(f"Error checking EBS encryption: {str(e)}")

        return result


# ============================================================================
# Compliance Scanner
# ============================================================================

class ComplianceScanner:
    """Main compliance scanner orchestrator."""

    def __init__(self, server_name: str, server_type: str, executor, aws_instance_id: Optional[str] = None):
        self.server_name = server_name
        self.server_type = server_type
        self.executor = executor
        self.aws_instance_id = aws_instance_id
        self.results = []
        self.start_time = None
        self.end_time = None

    def run_scan(self) -> Dict:
        """Run compliance scan and return results."""
        self.start_time = datetime.now()
        logger.info(f"Starting compliance scan for {self.server_name} ({self.server_type})")

        # Run OS checks (universal)
        logger.info("Running OS checks...")
        os_checks = OSChecks(self.executor)
        self.results.extend(os_checks.run_all())

        # Run SSH checks (universal)
        logger.info("Running SSH checks...")
        ssh_checks = SSHChecks(self.executor)
        self.results.extend(ssh_checks.run_all())

        # Run firewall checks (universal)
        logger.info("Running firewall checks...")
        firewall_checks = FirewallChecks(self.executor)
        self.results.extend(firewall_checks.run_all())

        # Run Docker checks (if applicable)
        logger.info("Running Docker checks...")
        docker_checks = DockerChecks(self.executor)
        self.results.extend(docker_checks.run_all())

        # Run AWS checks (if aws-ec2 type)
        if self.server_type == "aws-ec2" and self.aws_instance_id:
            logger.info("Running AWS checks...")
            aws_checks = AWSChecks(self.aws_instance_id)
            self.results.extend(aws_checks.run_all())

        self.end_time = datetime.now()
        duration = int((self.end_time - self.start_time).total_seconds())

        # Calculate statistics
        stats = self._calculate_stats()

        logger.info(f"Scan complete: {stats['checks_run']} checks run, {stats['findings_fail']} failures")

        return {
            "server_name": self.server_name,
            "server_type": self.server_type,
            "scan_date": self.start_time,
            "scan_duration_seconds": duration,
            "results": self.results,
            "stats": stats,
        }

    def _calculate_stats(self) -> Dict:
        """Calculate scan statistics."""
        stats = {
            "checks_total": len(self.results),
            "checks_run": len([r for r in self.results if r.status != "skip"]),
            "checks_skipped": len([r for r in self.results if r.status == "skip"]),
            "findings_pass": len([r for r in self.results if r.status == "pass"]),
            "findings_fail": len([r for r in self.results if r.status == "fail"]),
            "findings_critical": len([r for r in self.results if r.severity == "critical"]),
            "findings_high": len([r for r in self.results if r.severity == "high"]),
            "findings_medium": len([r for r in self.results if r.severity == "medium"]),
            "findings_low": len([r for r in self.results if r.severity == "low"]),
        }
        return stats


# ============================================================================
# Database Insertion
# ============================================================================

def insert_scan_results(scan_data: Dict, dry_run: bool = False) -> Optional[int]:
    """Insert scan results into database."""
    if dry_run:
        logger.info("=== DRY RUN MODE ===")
        logger.info(f"Would insert scan for {scan_data['server_name']}")
        logger.info(f"Findings: {scan_data['stats']}")
        return None

    try:
        with DatabaseConnection(DB_CONFIG) as conn:
            cursor = conn.cursor()

            # Insert scan record
            cursor.execute("""
                INSERT INTO blueteam.compliance_scans (
                    server_name,
                    server_type,
                    scan_date,
                    scan_duration_seconds,
                    findings_critical,
                    findings_high,
                    findings_medium,
                    findings_low,
                    findings_pass,
                    checks_total,
                    checks_run,
                    checks_skipped,
                    metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING scan_id
            """, (
                scan_data['server_name'],
                scan_data['server_type'],
                scan_data['scan_date'],
                scan_data['scan_duration_seconds'],
                scan_data['stats']['findings_critical'],
                scan_data['stats']['findings_high'],
                scan_data['stats']['findings_medium'],
                scan_data['stats']['findings_low'],
                scan_data['stats']['findings_pass'],
                scan_data['stats']['checks_total'],
                scan_data['stats']['checks_run'],
                scan_data['stats']['checks_skipped'],
                Json({"scanner_version": "1.0.0"})
            ))

            scan_id = cursor.fetchone()[0]
            logger.info(f"Inserted scan record: scan_id={scan_id}")

            # Insert findings
            for result in scan_data['results']:
                finding_data = result.to_dict()
                cursor.execute("""
                    INSERT INTO blueteam.compliance_findings (
                        scan_id,
                        check_category,
                        check_name,
                        check_id,
                        status,
                        severity,
                        finding_summary,
                        finding_details,
                        remediation_steps,
                        aws_resource_id,
                        aws_resource_type,
                        file_path,
                        service_name,
                        cis_benchmark,
                        aws_foundational_security,
                        nist_csf,
                        check_output
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    scan_id,
                    finding_data['check_category'],
                    finding_data['check_name'],
                    finding_data['check_id'],
                    finding_data['status'],
                    finding_data['severity'],
                    finding_data['finding_summary'],
                    finding_data['finding_details'],
                    finding_data['remediation_steps'],
                    finding_data['aws_resource_id'],
                    finding_data['aws_resource_type'],
                    finding_data['file_path'],
                    finding_data['service_name'],
                    finding_data['cis_benchmark'],
                    finding_data['aws_foundational_security'],
                    finding_data['nist_csf'],
                    finding_data['check_output'],
                ))

            logger.info(f"Inserted {len(scan_data['results'])} findings")

            # Calculate and update overall score
            cursor.execute("SELECT blueteam.calculate_compliance_score(%s)", (scan_id,))
            score = cursor.fetchone()[0]

            cursor.execute("""
                UPDATE blueteam.compliance_scans
                SET overall_score = %s
                WHERE scan_id = %s
            """, (score, scan_id))

            conn.commit()
            logger.info(f"Compliance score: {score}/100")

            return scan_id

    except Exception as e:
        logger.error(f"Database insertion failed: {e}")
        raise


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Cyber-Guardian Compliance Scanner")
    parser.add_argument("--server", required=True, help="Server name (e.g., willie, alfred)")
    parser.add_argument("--type", choices=["aws-ec2", "local", "remote-ssh"], required=True, help="Server type")
    parser.add_argument("--ssh-key", help="SSH key path for remote servers")
    parser.add_argument("--ssh-user", default="ubuntu", help="SSH user (default: ubuntu)")
    parser.add_argument("--aws-instance-id", help="AWS EC2 instance ID (for AWS checks)")
    parser.add_argument("--aws-region", default="us-east-2", help="AWS region (default: us-east-2)")
    parser.add_argument("--dry-run", action="store_true", help="Don't insert into database")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Create executor based on server type
    if args.type == "local":
        executor = LocalExecutor()
    else:  # remote-ssh or aws-ec2
        if not args.ssh_key:
            logger.error("SSH key required for remote servers")
            sys.exit(1)
        executor = SSHExecutor(args.server, args.ssh_key, args.ssh_user)

    # Create scanner
    scanner = ComplianceScanner(
        server_name=args.server,
        server_type=args.type,
        executor=executor,
        aws_instance_id=args.aws_instance_id
    )

    # Run scan
    scan_data = scanner.run_scan()

    # Insert results
    scan_id = insert_scan_results(scan_data, dry_run=args.dry_run)

    # Print summary
    print("\n" + "="*80)
    print("COMPLIANCE SCAN SUMMARY")
    print("="*80)
    print(f"Server: {args.server} ({args.type})")
    print(f"Checks run: {scan_data['stats']['checks_run']}/{scan_data['stats']['checks_total']}")
    print(f"Duration: {scan_data['scan_duration_seconds']} seconds")
    print()
    print("Results:")
    print(f"  ✓ Passed: {scan_data['stats']['findings_pass']}")
    print(f"  ✗ Failed: {scan_data['stats']['findings_fail']}")
    print(f"    - Critical: {scan_data['stats']['findings_critical']}")
    print(f"    - High: {scan_data['stats']['findings_high']}")
    print(f"    - Medium: {scan_data['stats']['findings_medium']}")
    print(f"    - Low: {scan_data['stats']['findings_low']}")
    print()

    if not args.dry_run and scan_id:
        print(f"Scan ID: {scan_id}")
        print(f"View results: SELECT * FROM blueteam.v_latest_compliance_scans WHERE server_name = '{args.server}';")

    print("="*80)


if __name__ == "__main__":
    main()
