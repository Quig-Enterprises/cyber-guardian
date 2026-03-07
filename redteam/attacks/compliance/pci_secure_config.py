"""PCI DSS 4.0 Requirement 2 — Secure System Configurations.

Verifies that vendor-supplied defaults are changed, unnecessary services
are disabled, SNMP is secured, and SSH is configured according to
hardening standards.
"""

import os
import re
import socket
import subprocess

from redteam.base import Attack, AttackResult, Severity, Status


# Default credentials to test on common services.
DEFAULT_CREDENTIALS = [
    # (service, host, port, username, password, description)
    ("postgresql", "localhost", 5432, "postgres", "postgres", "PostgreSQL default"),
    ("postgresql", "localhost", 5432, "postgres", "", "PostgreSQL empty password"),
    ("mysql", "localhost", 3306, "root", "", "MySQL root empty password"),
    ("mysql", "localhost", 3306, "root", "root", "MySQL root/root"),
]

# Ports for unnecessary services.
UNNECESSARY_SERVICES = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    79: "Finger",
    513: "rlogin",
    514: "rsh",
    515: "LPD",
    111: "rpcbind",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
}

# Weak SSH ciphers that must be rejected.
WEAK_SSH_CIPHERS = {
    "arcfour", "arcfour128", "arcfour256",
    "blowfish-cbc", "cast128-cbc", "3des-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
}

# Weak SSH MACs.
WEAK_SSH_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com",
    "hmac-sha1-96", "umac-64@openssh.com",
    "hmac-ripemd160",
}


class PCISecureConfigAttack(Attack):
    name = "compliance.pci_secure_config"
    category = "compliance"
    severity = Severity.HIGH
    description = "PCI DSS 4.0 Req 2 — Verify secure system configuration standards"

    def _check_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Return True if a TCP port is accepting connections."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        # ----------------------------------------------------------------
        # 1. Default credentials on common services
        # ----------------------------------------------------------------
        cred_findings: list[str] = []
        cred_tested = 0

        for svc, host, port, user, pwd, desc in DEFAULT_CREDENTIALS:
            if not self._check_port_open(host, port):
                continue

            cred_tested += 1
            try:
                if svc == "postgresql":
                    try:
                        import psycopg2
                        conn = psycopg2.connect(
                            host=host, port=port, user=user,
                            password=pwd, dbname="postgres",
                            connect_timeout=3,
                        )
                        conn.close()
                        cred_findings.append(
                            f"VULNERABLE: {desc} ({user}@{host}:{port}) — login succeeded"
                        )
                    except ImportError:
                        cred_findings.append(f"SKIPPED: {desc} — psycopg2 not installed")
                    except Exception:
                        pass  # Auth failed = good

                elif svc == "mysql":
                    try:
                        import pymysql
                        conn = pymysql.connect(
                            host=host, port=port, user=user,
                            password=pwd, database="mysql",
                            connect_timeout=3,
                        )
                        conn.close()
                        cred_findings.append(
                            f"VULNERABLE: {desc} ({user}@{host}:{port}) — login succeeded"
                        )
                    except ImportError:
                        # Fallback: try mysql CLI
                        try:
                            result = subprocess.run(
                                ["mysql", "-h", host, "-P", str(port),
                                 "-u", user, f"--password={pwd}",
                                 "-e", "SELECT 1;"],
                                capture_output=True, text=True, timeout=5,
                            )
                            if result.returncode == 0:
                                cred_findings.append(
                                    f"VULNERABLE: {desc} ({user}@{host}:{port}) — login succeeded"
                                )
                        except Exception:
                            pass
                    except Exception:
                        pass  # Auth failed = good

            except Exception:
                pass

        # Also test HTTP default credentials
        login_ep = self._get_login_endpoint()
        http_defaults = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("administrator", "administrator"),
        ]
        for user, pwd in http_defaults:
            cred_tested += 1
            try:
                status_code, body, headers = await client.post(
                    login_ep,
                    json_body={"email": user, "password": pwd},
                    cookies={},
                )
                if status_code == 200 and "error" not in body.lower():
                    cred_findings.append(
                        f"VULNERABLE: HTTP {user}/{pwd} at {login_ep} — login succeeded"
                    )
            except Exception:
                pass

        vulnerable_creds = [f for f in cred_findings if f.startswith("VULNERABLE")]
        if vulnerable_creds:
            cred_status = Status.VULNERABLE
            detail = (
                f"Default credentials accepted on {len(vulnerable_creds)} service(s). "
                "PCI DSS Req 2.2.2 requires changing all vendor-supplied defaults "
                "before deployment."
            )
        elif cred_tested == 0:
            cred_status = Status.DEFENDED
            detail = "No testable services found with open ports."
        else:
            cred_status = Status.DEFENDED
            detail = (
                f"Tested {cred_tested} default credential combinations. "
                "No defaults accepted."
            )

        results.append(self._make_result(
            variant="default_credentials",
            status=cred_status,
            severity=Severity.CRITICAL,
            evidence="\n".join(cred_findings) if cred_findings else f"Tested {cred_tested}, all rejected",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 2. Unnecessary services — check for insecure service ports
        # ----------------------------------------------------------------
        open_services: list[str] = []
        for port, svc_name in UNNECESSARY_SERVICES.items():
            if self._check_port_open("localhost", port, timeout=1.0):
                open_services.append(f"{svc_name} (port {port})")

        if open_services:
            svc_status = Status.VULNERABLE
            detail = (
                f"Found {len(open_services)} unnecessary/insecure service(s) running: "
                f"{', '.join(open_services)}. "
                "PCI DSS Req 2.2.4 requires disabling unnecessary services and protocols."
            )
        else:
            svc_status = Status.DEFENDED
            detail = (
                f"No unnecessary services detected on {len(UNNECESSARY_SERVICES)} "
                "checked ports."
            )

        results.append(self._make_result(
            variant="unnecessary_services",
            status=svc_status,
            severity=Severity.HIGH,
            evidence=f"Open: {open_services}" if open_services else "All clear",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 3. SNMP v1/v2c with default community strings
        # ----------------------------------------------------------------
        snmp_findings: list[str] = []
        snmp_port = 161
        if self._check_port_open("localhost", snmp_port, timeout=1.0):
            # Port is open — try default community strings
            community_strings = ["public", "private", "community"]
            for community in community_strings:
                try:
                    # Attempt SNMPv1/v2c GET using raw UDP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2.0)
                    # SNMPv1 GET-REQUEST for sysDescr (OID 1.3.6.1.2.1.1.1.0)
                    # Minimal SNMP v1 packet
                    snmp_get = (
                        b'\x30'  # SEQUENCE
                        b'\x26'  # length
                        b'\x02\x01\x00'  # version: 0 (SNMPv1)
                        b'\x04'  # OCTET STRING
                        + bytes([len(community)])
                        + community.encode()
                        + b'\xa0'  # GET-REQUEST
                        b'\x19'
                        b'\x02\x04\x00\x00\x00\x01'  # request-id
                        b'\x02\x01\x00'  # error-status
                        b'\x02\x01\x00'  # error-index
                        b'\x30\x0b'  # varbind list
                        b'\x30\x09'  # varbind
                        b'\x06\x05\x2b\x06\x01\x02\x01'  # OID
                        b'\x05\x00'  # NULL value
                    )
                    sock.sendto(snmp_get, ("localhost", snmp_port))
                    try:
                        data, addr = sock.recvfrom(4096)
                        if data:
                            snmp_findings.append(
                                f"SNMP responded to community '{community}'"
                            )
                    except socket.timeout:
                        pass
                    sock.close()
                except Exception:
                    pass

            # Also try snmpwalk if available
            for community in community_strings:
                try:
                    result = subprocess.run(
                        ["snmpwalk", "-v", "2c", "-c", community,
                         "localhost", "1.3.6.1.2.1.1.1.0"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        snmp_findings.append(
                            f"snmpwalk succeeded with community '{community}': "
                            f"{result.stdout.strip()[:100]}"
                        )
                except (FileNotFoundError, Exception):
                    pass

        if snmp_findings:
            snmp_status = Status.VULNERABLE
            detail = (
                f"SNMP v1/v2c responding with default community strings. "
                f"Findings: {'; '.join(snmp_findings)}. "
                "PCI DSS Req 2.2.7 requires SNMPv3 with authentication/encryption "
                "or SNMP disabled if not needed."
            )
        elif self._check_port_open("localhost", snmp_port, timeout=1.0):
            snmp_status = Status.PARTIAL
            detail = (
                "SNMP port 161 is open but default community strings were rejected. "
                "Verify SNMPv3 is in use."
            )
        else:
            snmp_status = Status.DEFENDED
            detail = "SNMP port 161 is not listening. Service appears disabled."

        results.append(self._make_result(
            variant="snmp_v1v2_check",
            status=snmp_status,
            severity=Severity.HIGH,
            evidence="; ".join(snmp_findings) if snmp_findings else "SNMP not accessible",
            details=detail,
        ))

        # ----------------------------------------------------------------
        # 4. SSH configuration hardening
        # ----------------------------------------------------------------
        sshd_config_paths = [
            "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d/",
        ]
        ssh_issues: list[str] = []
        ssh_config_content = ""

        # Read main config
        for cfg in sshd_config_paths:
            try:
                if os.path.isfile(cfg):
                    with open(cfg, "r") as f:
                        ssh_config_content += f.read() + "\n"
                elif os.path.isdir(cfg):
                    for fname in sorted(os.listdir(cfg)):
                        fpath = os.path.join(cfg, fname)
                        if fname.endswith(".conf"):
                            try:
                                with open(fpath, "r") as f:
                                    ssh_config_content += f.read() + "\n"
                            except (PermissionError, OSError):
                                continue
            except (PermissionError, FileNotFoundError):
                continue

        if ssh_config_content:
            # Check Protocol (modern OpenSSH defaults to 2, but explicit is better)
            protocol_match = re.search(
                r'^Protocol\s+(\S+)', ssh_config_content, re.MULTILINE
            )
            if protocol_match:
                proto = protocol_match.group(1)
                if proto != "2":
                    ssh_issues.append(f"Protocol set to {proto} instead of 2")

            # Check PermitRootLogin
            root_match = re.search(
                r'^PermitRootLogin\s+(\S+)', ssh_config_content, re.MULTILINE
            )
            if root_match:
                root_val = root_match.group(1).lower()
                if root_val not in ("no", "prohibit-password", "forced-commands-only"):
                    ssh_issues.append(f"PermitRootLogin is '{root_val}' (should be 'no')")
            else:
                ssh_issues.append(
                    "PermitRootLogin not explicitly set (default may allow root login)"
                )

            # Check for weak ciphers
            cipher_match = re.search(
                r'^Ciphers\s+(.+)', ssh_config_content, re.MULTILINE
            )
            if cipher_match:
                configured_ciphers = {c.strip().lower()
                                      for c in cipher_match.group(1).split(",")}
                weak_present = configured_ciphers & {c.lower() for c in WEAK_SSH_CIPHERS}
                if weak_present:
                    ssh_issues.append(f"Weak SSH ciphers configured: {weak_present}")

            # Check for weak MACs
            mac_match = re.search(
                r'^MACs\s+(.+)', ssh_config_content, re.MULTILINE
            )
            if mac_match:
                configured_macs = {m.strip().lower()
                                   for m in mac_match.group(1).split(",")}
                weak_mac_present = configured_macs & {m.lower() for m in WEAK_SSH_MACS}
                if weak_mac_present:
                    ssh_issues.append(f"Weak SSH MACs configured: {weak_mac_present}")

            # Check PasswordAuthentication (PCI prefers key-based + MFA)
            pwd_auth = re.search(
                r'^PasswordAuthentication\s+(\S+)', ssh_config_content, re.MULTILINE
            )
            if pwd_auth and pwd_auth.group(1).lower() == "yes":
                ssh_issues.append(
                    "PasswordAuthentication is 'yes' — key-based auth preferred for CDE"
                )

            # Check MaxAuthTries
            max_auth = re.search(
                r'^MaxAuthTries\s+(\d+)', ssh_config_content, re.MULTILINE
            )
            if max_auth:
                tries = int(max_auth.group(1))
                if tries > 6:
                    ssh_issues.append(
                        f"MaxAuthTries is {tries} (should be 6 or less)"
                    )

            if not ssh_issues:
                ssh_status = Status.DEFENDED
                detail = "SSH configuration meets PCI DSS hardening requirements."
            elif len(ssh_issues) <= 2:
                ssh_status = Status.PARTIAL
                detail = (
                    f"SSH has {len(ssh_issues)} configuration concern(s): "
                    + "; ".join(ssh_issues)
                )
            else:
                ssh_status = Status.VULNERABLE
                detail = (
                    f"SSH has {len(ssh_issues)} configuration issues: "
                    + "; ".join(ssh_issues)
                    + ". PCI DSS Req 2.2.1 requires secure configuration standards."
                )
            evidence = f"Issues: {ssh_issues}" if ssh_issues else "All checks passed"
        else:
            ssh_status = Status.ERROR
            detail = "Could not read sshd_config — unable to verify SSH hardening."
            evidence = f"Checked: {sshd_config_paths}"

        results.append(self._make_result(
            variant="ssh_config",
            status=ssh_status,
            severity=Severity.HIGH,
            evidence=evidence,
            details=detail,
        ))

        return results
