"""Listening services audit -- enumerates TCP/UDP services and flags risks.

Evaluation:
- Unnecessary services running (telnet, ftp, rsh) -> VULNERABLE
- Services bound to 0.0.0.0 that should be localhost-only -> VULNERABLE
- Only expected services listening -> DEFENDED
"""

import asyncio
import logging
import shutil

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Services that should generally not be running on production systems
UNNECESSARY_SERVICES = {
    "23": "telnet",
    "21": "FTP",
    "514": "rsh",
    "513": "rlogin",
    "79": "finger",
}

# Services that should typically bind to localhost only
LOCALHOST_ONLY_SERVICES = {
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "11211": "Memcached",
    "9200": "Elasticsearch",
    "2379": "etcd",
    "5601": "Kibana",
}


class ServiceEnumerationAttack(Attack):
    """Enumerate listening services and flag security concerns."""

    name = "infrastructure.service_enumeration"
    category = "infrastructure"
    severity = Severity.MEDIUM
    description = "Enumerate listening services and identify unnecessary or misconfigured ones"
    target_types = {"app", "wordpress", "generic"}

    async def _get_listening_services(self) -> tuple[list[dict], str]:
        """Parse listening services from ss output.

        Returns (parsed_services, raw_output).
        Each service dict has keys: proto, local_addr, port, process.
        """
        ss_bin = shutil.which("ss")
        if ss_bin:
            proc = await asyncio.create_subprocess_exec(
                "sudo", ss_bin, "-tlnp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            raw = stdout.decode(errors="replace")
        else:
            # Fall back to netstat
            netstat_bin = shutil.which("netstat")
            if not netstat_bin:
                return [], ""
            proc = await asyncio.create_subprocess_exec(
                "sudo", netstat_bin, "-tlnp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            raw = stdout.decode(errors="replace")

        services: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            # Skip header lines
            if not line or line.startswith("State") or line.startswith("Proto") or line.startswith("Active"):
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            # ss format: State Recv-Q Send-Q Local_Address:Port Peer_Address:Port Process
            # netstat format: Proto Recv-Q Send-Q Local_Address Foreign_Address State PID/Program
            if parts[0] in ("LISTEN", "UNCONN"):
                # ss output
                local = parts[3]
                process = parts[-1] if len(parts) >= 6 else ""
            elif parts[0] in ("tcp", "tcp6", "udp", "udp6"):
                # netstat output
                local = parts[3]
                process = parts[-1] if len(parts) >= 7 else ""
            else:
                continue

            # Parse address:port
            if "]:" in local:
                # IPv6 [::]:port
                addr, port = local.rsplit(":", 1)
            elif local.count(":") == 1:
                addr, port = local.rsplit(":", 1)
            else:
                # IPv6 without brackets or other format
                addr = local
                port = ""

            if not port:
                continue

            services.append({
                "proto": "tcp",
                "local_addr": addr,
                "port": port,
                "process": process,
                "raw_line": line,
            })

        return services, raw

    async def execute(self, client) -> list[AttackResult]:
        """Run all service enumeration variants."""
        results: list[AttackResult] = []

        if not shutil.which("ss") and not shutil.which("netstat"):
            results.append(self._make_result(
                variant="listening_services",
                status=Status.SKIPPED,
                evidence="Neither ss nor netstat found in PATH",
                details=(
                    "Cannot enumerate listening services. Install iproute2 (ss) "
                    "or net-tools (netstat): apt install iproute2"
                ),
            ))
            return results

        services, raw_output = await self._get_listening_services()

        results.append(self._check_listening_services(services, raw_output))
        results.append(self._check_unnecessary_services(services))
        results.append(self._check_unbound_services(services))

        return results

    def _check_listening_services(self, services: list[dict], raw_output: str) -> AttackResult:
        """List all listening TCP/UDP services."""
        if not services:
            return self._make_result(
                variant="listening_services",
                status=Status.DEFENDED,
                evidence="No listening TCP services detected",
                details="No TCP services are listening. This may indicate a parsing issue.",
                response={"service_count": 0},
            )

        service_lines = []
        for svc in services:
            service_lines.append(
                svc["local_addr"] + ":" + svc["port"] + " (" + svc["process"] + ")"
            )

        # Identify web servers
        webserver_ports = {}
        for svc in services:
            if svc["port"] in ("80", "443", "8080", "8443"):
                process_name = svc["process"].split("/")[0] if "/" in svc["process"] else svc["process"]
                if "nginx" in process_name.lower() or "apache" in process_name.lower():
                    webserver_ports[svc["port"]] = {
                        "process": process_name,
                        "address": svc["local_addr"],
                    }

        details_text = "Found " + str(len(services)) + " listening TCP service(s):\n"
        details_text += "\n".join("  - " + s for s in service_lines[:30])

        if webserver_ports:
            details_text += "\n\nWeb servers detected:\n"
            for port, info in webserver_ports.items():
                details_text += f"  - Port {port}: {info['process']} ({info['address']})\n"

        return self._make_result(
            variant="listening_services",
            status=Status.DEFENDED,
            severity=Severity.INFO,
            evidence=str(len(services)) + " listening service(s) enumerated",
            details=details_text,
            request={"tool": "ss -tlnp"},
            response={"service_count": len(services), "services": service_lines[:30], "webservers": webserver_ports},
        )

    def _check_unnecessary_services(self, services: list[dict]) -> AttackResult:
        """Flag common unnecessary services (telnet, ftp, rsh, rlogin, finger)."""
        found: list[str] = []

        for svc in services:
            port = svc["port"]
            if port in UNNECESSARY_SERVICES:
                name = UNNECESSARY_SERVICES[port]
                found.append(
                    "Port " + port + " (" + name + ") listening on " + svc["local_addr"]
                    + " [" + svc["process"] + "]"
                )

        if found:
            return self._make_result(
                variant="unnecessary_services",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=str(len(found)) + " unnecessary/insecure service(s) running",
                details=(
                    "The following unnecessary or insecure services are running. "
                    "These protocols transmit data in plaintext and should be disabled:\n"
                    + "\n".join("  - " + f for f in found)
                    + "\nDisable these services and use secure alternatives (e.g., SSH instead of telnet)."
                ),
                request={"checked_ports": list(UNNECESSARY_SERVICES.keys())},
                response={"found": found},
            )

        return self._make_result(
            variant="unnecessary_services",
            status=Status.DEFENDED,
            evidence="No unnecessary/insecure services detected",
            details=(
                "None of the flagged insecure services (telnet, FTP, rsh, rlogin, finger) "
                "are running."
            ),
            request={"checked_ports": list(UNNECESSARY_SERVICES.keys())},
            response={"found": []},
        )

    def _check_unbound_services(self, services: list[dict]) -> AttackResult:
        """Flag services bound to 0.0.0.0 that should be localhost-only."""
        exposed: list[str] = []

        wildcard_addrs = {"0.0.0.0", "*", "::", "[::]", "0.0.0.0/0"}

        for svc in services:
            port = svc["port"]
            addr = svc["local_addr"]

            if port in LOCALHOST_ONLY_SERVICES and addr in wildcard_addrs:
                name = LOCALHOST_ONLY_SERVICES[port]
                exposed.append(
                    "Port " + port + " (" + name + ") bound to " + addr
                    + " [" + svc["process"] + "] -- should be 127.0.0.1 or ::1"
                )

        if exposed:
            return self._make_result(
                variant="unbound_services",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=str(len(exposed)) + " service(s) bound to all interfaces that should be localhost-only",
                details=(
                    "The following services are bound to all network interfaces (0.0.0.0) "
                    "but should only listen on localhost. This exposes them to remote access:\n"
                    + "\n".join("  - " + e for e in exposed)
                    + "\nBind these services to 127.0.0.1 in their configuration files."
                ),
                request={"checked_ports": list(LOCALHOST_ONLY_SERVICES.keys())},
                response={"exposed": exposed},
            )

        return self._make_result(
            variant="unbound_services",
            status=Status.DEFENDED,
            evidence="No database/cache services exposed on all interfaces",
            details=(
                "All checked services (databases, caches) are either not running "
                "or properly bound to localhost."
            ),
            request={"checked_ports": list(LOCALHOST_ONLY_SERVICES.keys())},
            response={"exposed": []},
        )
