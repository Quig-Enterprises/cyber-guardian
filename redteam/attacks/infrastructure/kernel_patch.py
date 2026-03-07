"""Kernel and OS patch level audit -- checks for outdated kernel and pending updates.

Evaluation:
- Kernel version is EOL or very old -> VULNERABLE
- Security updates pending -> PARTIAL
- Reboot required after updates -> PARTIAL
- Kernel current, no pending updates -> DEFENDED
"""

import asyncio
import logging
import os
import platform
import re
import shutil

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Kernel major versions known to be EOL (no longer receiving updates)
# Updated periodically -- conservative list of clearly EOL versions
EOL_KERNEL_MAJORS = {
    "2.6", "3.0", "3.2", "3.4", "3.10", "3.12", "3.14", "3.16", "3.18",
    "4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8",
    "4.9", "4.10", "4.11", "4.12", "4.13", "4.14", "4.15", "4.16",
    "4.17", "4.18", "4.19", "4.20",
    "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8",
    "5.9", "5.10", "5.11", "5.12", "5.13", "5.14",
}


class KernelPatchAttack(Attack):
    """Audit kernel version and OS patch level."""

    name = "infrastructure.kernel_patch"
    category = "infrastructure"
    severity = Severity.MEDIUM
    description = "Check kernel version and pending security updates"
    target_types = {"app", "wordpress", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all kernel/patch audit variants."""
        results: list[AttackResult] = []

        results.append(self._check_kernel_version())
        results.append(await self._check_pending_updates())
        results.append(self._check_reboot_required())

        return results

    def _check_kernel_version(self) -> AttackResult:
        """Check running kernel version and flag if known EOL."""
        kernel_release = platform.release()
        kernel_version = platform.version()

        # Extract major.minor from kernel release (e.g., "5.15.0-91-generic" -> "5.15")
        match = re.match(r"(\d+\.\d+)", kernel_release)
        if not match:
            return self._make_result(
                variant="kernel_version",
                status=Status.ERROR,
                evidence="Could not parse kernel version: " + kernel_release,
                details="Kernel release string '" + kernel_release + "' does not match expected format.",
                response={"kernel_release": kernel_release},
            )

        major_minor = match.group(1)

        if major_minor in EOL_KERNEL_MAJORS:
            return self._make_result(
                variant="kernel_version",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="Kernel " + kernel_release + " (series " + major_minor + ") is EOL",
                details=(
                    "Running kernel " + kernel_release + " which belongs to the "
                    + major_minor + " series. "
                    "This kernel series is end-of-life and no longer receives security patches. "
                    "Upgrade to a supported kernel version."
                ),
                request={"tool": "uname -r"},
                response={
                    "kernel_release": kernel_release,
                    "kernel_version": kernel_version,
                    "series": major_minor,
                    "eol": True,
                },
            )

        return self._make_result(
            variant="kernel_version",
            status=Status.DEFENDED,
            evidence="Kernel " + kernel_release + " (series " + major_minor + ") is not in known EOL list",
            details=(
                "Running kernel " + kernel_release + ". The " + major_minor + " series is not flagged "
                "as end-of-life. Verify with your distribution's support lifecycle."
            ),
            request={"tool": "uname -r"},
            response={
                "kernel_release": kernel_release,
                "kernel_version": kernel_version,
                "series": major_minor,
                "eol": False,
            },
        )

    async def _check_pending_updates(self) -> AttackResult:
        """Check for pending security updates."""
        # Try apt (Debian/Ubuntu)
        if shutil.which("apt"):
            return await self._check_apt_updates()

        # Try yum (RHEL/CentOS)
        if shutil.which("yum"):
            return await self._check_yum_updates()

        # Try dnf (Fedora/RHEL 8+)
        if shutil.which("dnf"):
            return await self._check_dnf_updates()

        return self._make_result(
            variant="pending_updates",
            status=Status.SKIPPED,
            evidence="No supported package manager found (checked apt, yum, dnf)",
            details=(
                "Could not check for pending updates. Supported package managers: "
                "apt (Debian/Ubuntu), yum (RHEL/CentOS), dnf (Fedora/RHEL 8+)."
            ),
        )

    async def _check_apt_updates(self) -> AttackResult:
        """Check pending updates via apt."""
        proc = await asyncio.create_subprocess_exec(
            "apt", "list", "--upgradable",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode(errors="replace")

        # Filter for security updates
        all_upgradable: list[str] = []
        security_upgradable: list[str] = []

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Listing") or line.startswith("WARNING"):
                continue
            all_upgradable.append(line)
            if "security" in line.lower():
                security_upgradable.append(line)

        if security_upgradable:
            truncation_note = ""
            if len(security_upgradable) > 15:
                truncation_note = "\n  ... and " + str(len(security_upgradable) - 15) + " more"
            return self._make_result(
                variant="pending_updates",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=(
                    str(len(security_upgradable)) + " pending security update(s) "
                    "out of " + str(len(all_upgradable)) + " total"
                ),
                details=(
                    "Security updates are available and should be applied promptly:\n"
                    + "\n".join("  - " + u for u in security_upgradable[:15])
                    + truncation_note
                    + "\nApply with: sudo apt update && sudo apt upgrade"
                ),
                request={"tool": "apt list --upgradable"},
                response={
                    "total_upgradable": len(all_upgradable),
                    "security_upgradable": len(security_upgradable),
                    "security_packages": security_upgradable[:15],
                },
            )

        if all_upgradable:
            return self._make_result(
                variant="pending_updates",
                status=Status.PARTIAL,
                severity=Severity.LOW,
                evidence=str(len(all_upgradable)) + " pending update(s), none flagged as security",
                details=(
                    "There are " + str(len(all_upgradable)) + " pending package update(s), but none "
                    "are explicitly flagged as security updates. Consider applying them:\n"
                    + "\n".join("  - " + u for u in all_upgradable[:10])
                ),
                request={"tool": "apt list --upgradable"},
                response={
                    "total_upgradable": len(all_upgradable),
                    "security_upgradable": 0,
                },
            )

        return self._make_result(
            variant="pending_updates",
            status=Status.DEFENDED,
            evidence="No pending updates",
            details="All packages are up to date. No pending updates found.",
            request={"tool": "apt list --upgradable"},
            response={"total_upgradable": 0, "security_upgradable": 0},
        )

    async def _check_yum_updates(self) -> AttackResult:
        """Check pending updates via yum."""
        proc = await asyncio.create_subprocess_exec(
            "yum", "check-update", "--security", "--quiet",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode(errors="replace")

        # yum check-update returns exit code 100 if updates available
        updates = [
            line.strip() for line in output.splitlines()
            if line.strip() and not line.startswith("Obsoleting")
        ]

        if proc.returncode == 100 and updates:
            return self._make_result(
                variant="pending_updates",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=str(len(updates)) + " pending security update(s)",
                details=(
                    "Security updates are available:\n"
                    + "\n".join("  - " + u for u in updates[:15])
                    + "\nApply with: sudo yum update --security"
                ),
                request={"tool": "yum check-update --security"},
                response={"security_updates": len(updates)},
            )

        return self._make_result(
            variant="pending_updates",
            status=Status.DEFENDED,
            evidence="No pending security updates (yum)",
            details="No security updates pending according to yum.",
            request={"tool": "yum check-update --security"},
            response={"security_updates": 0},
        )

    async def _check_dnf_updates(self) -> AttackResult:
        """Check pending updates via dnf."""
        proc = await asyncio.create_subprocess_exec(
            "dnf", "check-update", "--security", "--quiet",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode(errors="replace")

        updates = [
            line.strip() for line in output.splitlines()
            if line.strip() and not line.startswith("Obsoleting")
        ]

        if proc.returncode == 100 and updates:
            return self._make_result(
                variant="pending_updates",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=str(len(updates)) + " pending security update(s)",
                details=(
                    "Security updates are available:\n"
                    + "\n".join("  - " + u for u in updates[:15])
                    + "\nApply with: sudo dnf update --security"
                ),
                request={"tool": "dnf check-update --security"},
                response={"security_updates": len(updates)},
            )

        return self._make_result(
            variant="pending_updates",
            status=Status.DEFENDED,
            evidence="No pending security updates (dnf)",
            details="No security updates pending according to dnf.",
            request={"tool": "dnf check-update --security"},
            response={"security_updates": 0},
        )

    def _check_reboot_required(self) -> AttackResult:
        """Check if a reboot is required after applying updates."""
        reboot_file = "/var/run/reboot-required"
        pkgs_file = "/var/run/reboot-required.pkgs"

        if os.path.isfile(reboot_file):
            packages = ""
            if os.path.isfile(pkgs_file):
                try:
                    with open(pkgs_file, "r") as fh:
                        packages = fh.read().strip()
                except OSError:
                    pass

            details = "A system reboot is required to apply installed updates."
            if packages:
                pkg_list = packages.splitlines()
                details += (
                    "\nPackages requiring reboot (" + str(len(pkg_list)) + "):\n"
                    + "\n".join("  - " + p for p in pkg_list[:10])
                )

            return self._make_result(
                variant="reboot_required",
                status=Status.PARTIAL,
                severity=Severity.MEDIUM,
                evidence=reboot_file + " exists -- reboot required",
                details=details,
                request={"checked": reboot_file},
                response={
                    "reboot_required": True,
                    "packages": packages.splitlines()[:10] if packages else [],
                },
            )

        return self._make_result(
            variant="reboot_required",
            status=Status.DEFENDED,
            evidence=reboot_file + " does not exist -- no reboot required",
            details="No reboot is required. The system is running with up-to-date kernel and libraries.",
            request={"checked": reboot_file},
            response={"reboot_required": False},
        )
