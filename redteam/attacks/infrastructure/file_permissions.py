"""File permission audit -- checks for insecure file and directory permissions.

Evaluation:
- World-writable files in /etc or /var/www -> VULNERABLE
- Unexpected SUID binaries -> VULNERABLE
- Sensitive config files with loose permissions -> VULNERABLE
- Web root overly permissive -> PARTIAL
- All permissions properly restricted -> DEFENDED
"""

import asyncio
import logging
import os
import stat

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Known legitimate SUID binaries (common across distros)
EXPECTED_SUID = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/bin/crontab",
    "/usr/bin/at",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/snapd/snap-confine",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/sbin/pppd",
    "/bin/su",
    "/bin/mount",
    "/bin/umount",
    "/bin/ping",
    "/usr/bin/ping",
    "/snap/snapd/current/usr/lib/snapd/snap-confine",
    "/usr/bin/sudo.ws",
    "/usr/bin/ntfs-3g",
    "/usr/lib/cargo/bin/sudo",
    "/usr/lib/cargo/bin/su",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
}

# Sensitive files and their maximum allowed permissions (octal)
SENSITIVE_FILES = {
    "/etc/shadow": 0o640,
    "/etc/shadow-": 0o640,
    "/etc/gshadow": 0o640,
    "/etc/gshadow-": 0o640,
    "/etc/ssh/ssh_host_rsa_key": 0o600,
    "/etc/ssh/ssh_host_ecdsa_key": 0o600,
    "/etc/ssh/ssh_host_ed25519_key": 0o600,
    "/etc/ssh/sshd_config": 0o644,
    "/etc/ssl/private": 0o700,
}


class FilePermissionsAttack(Attack):
    """Audit file and directory permissions for security weaknesses."""

    name = "infrastructure.file_permissions"
    category = "infrastructure"
    severity = Severity.HIGH
    description = "Check for insecure file permissions on critical system files"
    target_types = {"app", "wordpress", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run all file permission audit variants."""
        results: list[AttackResult] = []

        results.append(await self._check_world_writable())
        results.append(await self._check_suid_binaries())
        results.append(self._check_sensitive_configs())
        results.append(await self._check_web_root_perms())

        return results

    async def _run_find(self, *args: str) -> tuple[int, str, str]:
        """Run a find command with optional timeout for AWS mode."""
        cmd: list[str] = []
        if self._is_aws_mode():
            timeout_bin = "/usr/bin/timeout"
            if not os.path.isfile(timeout_bin):
                timeout_bin = "timeout"
            cmd = [timeout_bin, "30"]
        cmd.extend(["find"] + list(args))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return (
            proc.returncode,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )

    async def _check_world_writable(self) -> AttackResult:
        """Find world-writable files in key directories (/etc, /var/www)."""
        search_dirs = ["/etc", "/var/www"]
        all_writable: list[str] = []

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            rc, stdout, stderr = await self._run_find(
                search_dir, "-perm", "-o+w", "-type", "f",
                "-not", "-path", "*/proc/*",
                "-not", "-path", "*/sys/*",
            )
            files = [f.strip() for f in stdout.splitlines() if f.strip()]
            for f in files:
                all_writable.append(f)

        if all_writable:
            truncation_note = ""
            if len(all_writable) > 20:
                truncation_note = "\n  ... and " + str(len(all_writable) - 20) + " more"
            return self._make_result(
                variant="world_writable",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=str(len(all_writable)) + " world-writable file(s) found",
                details=(
                    "World-writable files allow any user on the system to modify them. "
                    "This can lead to privilege escalation or configuration tampering:\n"
                    + "\n".join("  - " + f for f in all_writable[:20])
                    + truncation_note
                    + "\nFix with: chmod o-w <file>"
                ),
                request={"search_dirs": search_dirs},
                response={"count": len(all_writable), "files": all_writable[:20]},
            )

        return self._make_result(
            variant="world_writable",
            status=Status.DEFENDED,
            evidence="No world-writable files found in /etc or /var/www",
            details="No world-writable files were detected in critical directories.",
            request={"search_dirs": search_dirs},
            response={"count": 0},
        )

    async def _check_suid_binaries(self) -> AttackResult:
        """Find SUID binaries and flag unexpected ones."""
        search_dirs = ["/usr", "/bin", "/sbin"]
        if self._is_aws_mode():
            # Limit scope in AWS to avoid excessive I/O
            search_dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin"]

        all_suid: list[str] = []
        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            rc, stdout, stderr = await self._run_find(
                search_dir, "-perm", "-4000", "-type", "f",
            )
            files = [f.strip() for f in stdout.splitlines() if f.strip()]
            all_suid.extend(files)

        unexpected = [f for f in all_suid if f not in EXPECTED_SUID]

        if unexpected:
            truncation_note = ""
            if len(unexpected) > 20:
                truncation_note = "\n  ... and " + str(len(unexpected) - 20) + " more"
            return self._make_result(
                variant="suid_binaries",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=(
                    str(len(unexpected)) + " unexpected SUID binary(ies) found out of "
                    + str(len(all_suid)) + " total"
                ),
                details=(
                    "SUID binaries run with elevated privileges and are common privilege "
                    "escalation targets. The following SUID binaries are not in the expected list:\n"
                    + "\n".join("  - " + f for f in unexpected[:20])
                    + truncation_note
                    + "\nReview each binary and remove the SUID bit if not needed: "
                    "chmod u-s <file>"
                ),
                request={"search_dirs": search_dirs},
                response={
                    "total_suid": len(all_suid),
                    "unexpected": unexpected[:20],
                    "expected_matched": len(all_suid) - len(unexpected),
                },
            )

        return self._make_result(
            variant="suid_binaries",
            status=Status.DEFENDED,
            evidence=str(len(all_suid)) + " SUID binary(ies) found, all in expected list",
            details="All SUID binaries are recognized as standard system binaries.",
            request={"search_dirs": search_dirs},
            response={"total_suid": len(all_suid), "unexpected": []},
        )

    def _check_sensitive_configs(self) -> AttackResult:
        """Check permissions on sensitive files (/etc/shadow, SSH keys, etc.)."""
        issues: list[str] = []
        checked = 0

        for filepath, max_perm in SENSITIVE_FILES.items():
            if not os.path.exists(filepath):
                continue
            checked += 1
            try:
                st = os.stat(filepath)
                actual_perm = stat.S_IMODE(st.st_mode)

                # Check if actual permissions are more permissive than allowed
                excess = actual_perm & ~max_perm
                if excess:
                    actual_str = oct(actual_perm)
                    max_str = oct(max_perm)
                    issues.append(
                        filepath + ": " + actual_str + " (should be " + max_str + " or stricter)"
                    )
            except OSError as exc:
                logger.debug("Could not stat %s: %s", filepath, exc)

        if not checked:
            return self._make_result(
                variant="sensitive_configs",
                status=Status.SKIPPED,
                evidence="No sensitive config files found to check",
                details="None of the expected sensitive files exist on this system.",
                response={"checked": 0},
            )

        if issues:
            return self._make_result(
                variant="sensitive_configs",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=str(len(issues)) + " sensitive file(s) with overly permissive permissions",
                details=(
                    "Sensitive configuration files have permissions that are too loose. "
                    "This may allow unauthorized users to read credentials or private keys:\n"
                    + "\n".join("  - " + i for i in issues)
                ),
                request={"files_checked": list(SENSITIVE_FILES.keys())},
                response={"issues": issues, "checked": checked},
            )

        return self._make_result(
            variant="sensitive_configs",
            status=Status.DEFENDED,
            evidence="All " + str(checked) + " sensitive file(s) have correct permissions",
            details="All checked sensitive files have appropriately restrictive permissions.",
            request={"files_checked": list(SENSITIVE_FILES.keys())},
            response={"checked": checked, "issues": []},
        )

    async def _check_web_root_perms(self) -> AttackResult:
        """Check web root permissions for overly permissive settings."""
        web_roots = ["/var/www/html", "/var/www"]
        issues: list[str] = []
        checked_root = None

        for web_root in web_roots:
            if os.path.isdir(web_root):
                checked_root = web_root
                break

        if not checked_root:
            return self._make_result(
                variant="web_root_perms",
                status=Status.SKIPPED,
                evidence="No web root directory found (/var/www/html, /var/www)",
                details="Web root directory does not exist; skipping permission check.",
            )

        # Check the root directory itself
        try:
            st = os.stat(checked_root)
            perm = stat.S_IMODE(st.st_mode)
            if perm & stat.S_IWOTH:
                issues.append(checked_root + ": world-writable (" + oct(perm) + ")")
            if perm & stat.S_IWGRP and perm & stat.S_IXOTH:
                issues.append(
                    checked_root + ": group-writable and world-executable (" + oct(perm) + ")"
                )
        except OSError:
            pass

        # Check for world-writable PHP files in web root (limited depth)
        rc, stdout, stderr = await self._run_find(
            checked_root, "-maxdepth", "3", "-perm", "-o+w",
            "-type", "f", "-name", "*.php",
        )
        writable_php = [f.strip() for f in stdout.splitlines() if f.strip()]
        if writable_php:
            issues.append(
                str(len(writable_php)) + " world-writable PHP file(s): "
                + ", ".join(writable_php[:5])
            )

        # Check for overly permissive config files in web root
        config_patterns = [".env", "wp-config.php", "config.php", ".htaccess"]
        for pattern in config_patterns:
            rc, stdout, stderr = await self._run_find(
                checked_root, "-maxdepth", "3", "-name", pattern, "-type", "f",
            )
            for filepath in stdout.splitlines():
                filepath = filepath.strip()
                if not filepath:
                    continue
                try:
                    st = os.stat(filepath)
                    perm = stat.S_IMODE(st.st_mode)
                    if perm & stat.S_IROTH:
                        issues.append(
                            filepath + ": world-readable (" + oct(perm) + "), "
                            "may contain credentials"
                        )
                except OSError:
                    pass

        if issues:
            return self._make_result(
                variant="web_root_perms",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=str(len(issues)) + " permission issue(s) in web root",
                details=(
                    "Permission issues found in " + checked_root + ":\n"
                    + "\n".join("  - " + i for i in issues[:15])
                    + "\nEnsure web files are owned by www-data with minimal permissions "
                    "(644 for files, 755 for directories)."
                ),
                request={"web_root": checked_root},
                response={"issues": issues[:15]},
            )

        return self._make_result(
            variant="web_root_perms",
            status=Status.DEFENDED,
            evidence="Web root " + checked_root + " permissions are properly configured",
            details="No overly permissive files or directories found in the web root.",
            request={"web_root": checked_root},
            response={"issues": []},
        )
