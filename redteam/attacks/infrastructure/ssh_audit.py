"""SSH configuration audit -- checks sshd_config for security best practices.

Evaluation:
- PermitRootLogin enabled -> VULNERABLE
- PasswordAuthentication enabled -> VULNERABLE
- SSH protocol version 1 allowed -> VULNERABLE
- Weak ciphers/MACs in use -> VULNERABLE
- MaxAuthTries > 3 -> PARTIAL
- All settings secure -> DEFENDED
"""

import logging
import os

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

# Ciphers considered weak or broken
WEAK_CIPHERS = {
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
    "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc",
}

# MACs considered weak
WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com",
    "hmac-ripemd160", "hmac-ripemd160@openssh.com",
}

# Key exchange algorithms considered weak
WEAK_KEX = {
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}


class SSHAuditAttack(Attack):
    """Audit SSH server configuration for security weaknesses."""

    name = "infrastructure.ssh_audit"
    category = "infrastructure"
    severity = Severity.HIGH
    description = "Check SSH server configuration for insecure settings"
    target_types = {"app", "wordpress", "generic"}

    def _read_sshd_config(self) -> dict:
        """Parse sshd_config into a dict of lowercase key -> value.

        Returns an empty dict if the file cannot be read.
        Later directives override earlier ones (matching OpenSSH behavior
        for the first-match rule, but we just collect all for auditing).
        """
        config = {}
        try:
            if not os.path.isfile(SSHD_CONFIG_PATH):
                return config
            with open(SSHD_CONFIG_PATH, "r") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        config[key.lower()] = value
        except PermissionError:
            logger.warning("Permission denied reading %s", SSHD_CONFIG_PATH)
        except OSError as exc:
            logger.warning("Could not read %s: %s", SSHD_CONFIG_PATH, exc)
        return config

    async def execute(self, client) -> list[AttackResult]:
        """Run all SSH configuration audit variants."""
        results: list[AttackResult] = []

        config = self._read_sshd_config()
        if not config:
            results.append(self._make_result(
                variant="sshd_config_read",
                status=Status.SKIPPED,
                evidence=f"Could not read {SSHD_CONFIG_PATH}",
                details=(
                    f"Unable to read {SSHD_CONFIG_PATH}. "
                    "Ensure the file exists and the process has read permissions."
                ),
            ))
            return results

        results.append(self._check_root_login(config))
        results.append(self._check_password_auth(config))
        results.append(self._check_protocol_version(config))
        results.append(self._check_weak_ciphers(config))
        results.append(self._check_max_auth_tries(config))

        return results

    def _check_root_login(self, config: dict) -> AttackResult:
        """Check if PermitRootLogin is enabled."""
        value = config.get("permitrootlogin", "").lower()

        if not value:
            # OpenSSH >= 7.0 defaults to prohibit-password
            return self._make_result(
                variant="root_login",
                status=Status.PARTIAL,
                evidence="PermitRootLogin not explicitly set in sshd_config",
                details=(
                    "PermitRootLogin is not explicitly configured. "
                    "Modern OpenSSH defaults to 'prohibit-password', but explicit "
                    "configuration is recommended."
                ),
                request={"config_file": SSHD_CONFIG_PATH},
                response={"permitrootlogin": "not set (default)"},
            )

        if value == "yes":
            return self._make_result(
                variant="root_login",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"PermitRootLogin = {value}",
                details=(
                    "Root login via SSH is fully enabled. An attacker who obtains "
                    "or brute-forces the root password can log in directly. "
                    "Set PermitRootLogin to 'no' or 'prohibit-password'."
                ),
                request={"config_file": SSHD_CONFIG_PATH},
                response={"permitrootlogin": value},
            )

        if value in ("no", "prohibit-password", "without-password", "forced-commands-only"):
            return self._make_result(
                variant="root_login",
                status=Status.DEFENDED,
                evidence=f"PermitRootLogin = {value}",
                details="Root login is properly restricted.",
                request={"config_file": SSHD_CONFIG_PATH},
                response={"permitrootlogin": value},
            )

        return self._make_result(
            variant="root_login",
            status=Status.PARTIAL,
            evidence=f"PermitRootLogin = {value} (unexpected value)",
            details=f"Unrecognized PermitRootLogin value: '{value}'. Review manually.",
            request={"config_file": SSHD_CONFIG_PATH},
            response={"permitrootlogin": value},
        )

    def _check_password_auth(self, config: dict) -> AttackResult:
        """Check if PasswordAuthentication is enabled (should be key-only)."""
        value = config.get("passwordauthentication", "").lower()

        if not value or value == "yes":
            is_default = not value
            return self._make_result(
                variant="password_auth",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=(
                    "PasswordAuthentication not set (defaults to yes)"
                    if is_default else f"PasswordAuthentication = {value}"
                ),
                details=(
                    "Password-based SSH authentication is enabled. This exposes the "
                    "server to brute-force attacks. Disable PasswordAuthentication "
                    "and use key-based authentication exclusively."
                ),
                request={"config_file": SSHD_CONFIG_PATH},
                response={"passwordauthentication": value or "not set (default: yes)"},
            )

        if value == "no":
            return self._make_result(
                variant="password_auth",
                status=Status.DEFENDED,
                evidence="PasswordAuthentication = no",
                details="Password authentication is disabled; key-based auth only.",
                request={"config_file": SSHD_CONFIG_PATH},
                response={"passwordauthentication": value},
            )

        return self._make_result(
            variant="password_auth",
            status=Status.PARTIAL,
            evidence=f"PasswordAuthentication = {value} (unexpected value)",
            details=f"Unrecognized PasswordAuthentication value: '{value}'. Review manually.",
            request={"config_file": SSHD_CONFIG_PATH},
            response={"passwordauthentication": value},
        )

    def _check_protocol_version(self, config: dict) -> AttackResult:
        """Check SSH protocol version (should be 2 only)."""
        value = config.get("protocol", "").strip()

        if not value:
            # OpenSSH >= 7.4 removed Protocol 1 support entirely
            return self._make_result(
                variant="protocol_version",
                status=Status.DEFENDED,
                evidence="Protocol directive not set (modern OpenSSH defaults to 2 only)",
                details=(
                    "The Protocol directive is absent, which is correct for modern "
                    "OpenSSH (>= 7.4) where Protocol 1 support has been removed."
                ),
                request={"config_file": SSHD_CONFIG_PATH},
                response={"protocol": "not set (default: 2)"},
            )

        if value == "2":
            return self._make_result(
                variant="protocol_version",
                status=Status.DEFENDED,
                evidence="Protocol = 2",
                details="Only SSH Protocol 2 is allowed.",
                request={"config_file": SSHD_CONFIG_PATH},
                response={"protocol": value},
            )

        if "1" in value:
            return self._make_result(
                variant="protocol_version",
                status=Status.VULNERABLE,
                severity=Severity.CRITICAL,
                evidence=f"Protocol = {value}",
                details=(
                    "SSH Protocol 1 is enabled. Protocol 1 has known cryptographic "
                    "weaknesses and is vulnerable to man-in-the-middle attacks. "
                    "Set Protocol to '2' only."
                ),
                request={"config_file": SSHD_CONFIG_PATH},
                response={"protocol": value},
            )

        return self._make_result(
            variant="protocol_version",
            status=Status.PARTIAL,
            evidence=f"Protocol = {value} (unexpected value)",
            details=f"Unrecognized Protocol value: '{value}'. Review manually.",
            request={"config_file": SSHD_CONFIG_PATH},
            response={"protocol": value},
        )

    def _check_weak_ciphers(self, config: dict) -> AttackResult:
        """Check for weak ciphers, MACs, and key exchange algorithms."""
        findings: list[str] = []

        # Check ciphers
        ciphers_str = config.get("ciphers", "")
        if ciphers_str:
            configured_ciphers = {c.strip().lower() for c in ciphers_str.split(",")}
            weak_found = configured_ciphers & {c.lower() for c in WEAK_CIPHERS}
            if weak_found:
                findings.append(f"Weak ciphers: {', '.join(sorted(weak_found))}")

        # Check MACs
        macs_str = config.get("macs", "")
        if macs_str:
            configured_macs = {m.strip().lower() for m in macs_str.split(",")}
            weak_found = configured_macs & {m.lower() for m in WEAK_MACS}
            if weak_found:
                findings.append(f"Weak MACs: {', '.join(sorted(weak_found))}")

        # Check key exchange
        kex_str = config.get("kexalgorithms", "")
        if kex_str:
            configured_kex = {k.strip().lower() for k in kex_str.split(",")}
            weak_found = configured_kex & {k.lower() for k in WEAK_KEX}
            if weak_found:
                findings.append(f"Weak KEX: {', '.join(sorted(weak_found))}")

        if findings:
            return self._make_result(
                variant="weak_ciphers",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="; ".join(findings),
                details=(
                    "Weak cryptographic algorithms are configured for SSH:\n"
                    + "\n".join(f"  - {f}" for f in findings)
                    + "\nRemove these from sshd_config and restart sshd."
                ),
                request={"config_file": SSHD_CONFIG_PATH},
                response={
                    "ciphers": ciphers_str or "not set",
                    "macs": macs_str or "not set",
                    "kexalgorithms": kex_str or "not set",
                },
            )

        return self._make_result(
            variant="weak_ciphers",
            status=Status.DEFENDED,
            evidence="No weak ciphers, MACs, or KEX algorithms found in sshd_config",
            details=(
                "SSH cryptographic configuration does not include known weak algorithms. "
                "Note: if ciphers/MACs/KEX are not explicitly set, OpenSSH defaults apply."
            ),
            request={"config_file": SSHD_CONFIG_PATH},
            response={
                "ciphers": ciphers_str or "not set (defaults)",
                "macs": macs_str or "not set (defaults)",
                "kexalgorithms": kex_str or "not set (defaults)",
            },
        )

    def _check_max_auth_tries(self, config: dict) -> AttackResult:
        """Check MaxAuthTries setting (should be <= 3)."""
        value = config.get("maxauthtries", "").strip()

        if not value:
            # OpenSSH default is 6
            return self._make_result(
                variant="max_auth_tries",
                status=Status.PARTIAL,
                evidence="MaxAuthTries not set (OpenSSH default is 6)",
                details=(
                    "MaxAuthTries is not explicitly configured. OpenSSH defaults to 6, "
                    "which allows more brute-force attempts per connection than recommended. "
                    "Set MaxAuthTries to 3 or lower."
                ),
                request={"config_file": SSHD_CONFIG_PATH},
                response={"maxauthtries": "not set (default: 6)"},
            )

        try:
            max_tries = int(value)
        except ValueError:
            return self._make_result(
                variant="max_auth_tries",
                status=Status.ERROR,
                evidence=f"MaxAuthTries = {value} (non-integer)",
                details=f"Could not parse MaxAuthTries value: '{value}'",
                request={"config_file": SSHD_CONFIG_PATH},
                response={"maxauthtries": value},
            )

        if max_tries <= 3:
            return self._make_result(
                variant="max_auth_tries",
                status=Status.DEFENDED,
                evidence=f"MaxAuthTries = {max_tries}",
                details=f"MaxAuthTries is set to {max_tries}, limiting brute-force attempts per connection.",
                request={"config_file": SSHD_CONFIG_PATH},
                response={"maxauthtries": max_tries},
            )

        return self._make_result(
            variant="max_auth_tries",
            status=Status.PARTIAL,
            severity=Severity.MEDIUM,
            evidence=f"MaxAuthTries = {max_tries} (recommended: <= 3)",
            details=(
                f"MaxAuthTries is set to {max_tries}, allowing {max_tries} authentication "
                "attempts per connection. Reduce to 3 or lower to limit brute-force exposure."
            ),
            request={"config_file": SSHD_CONFIG_PATH},
            response={"maxauthtries": max_tries},
        )
