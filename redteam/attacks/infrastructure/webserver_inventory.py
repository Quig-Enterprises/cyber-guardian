"""Web server inventory -- detects installed web servers and running status.

Evaluation:
- Multiple web servers installed -> PARTIAL (potential confusion)
- Installed but not running -> INFO
- Running web server identified -> DEFENDED
- No web server detected -> INFO
"""

import asyncio
import logging
import shutil

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

WEB_SERVERS = {
    "nginx": {
        "packages": ["nginx", "nginx-core", "nginx-full"],
        "service": "nginx",
        "binary": "/usr/sbin/nginx",
    },
    "apache2": {
        "packages": ["apache2", "apache2-bin"],
        "service": "apache2",
        "binary": "/usr/sbin/apache2",
    },
    "lighttpd": {
        "packages": ["lighttpd"],
        "service": "lighttpd",
        "binary": "/usr/sbin/lighttpd",
    },
    "caddy": {
        "packages": ["caddy"],
        "service": "caddy",
        "binary": "/usr/bin/caddy",
    },
}


class WebServerInventoryAttack(Attack):
    """Inventory installed and running web servers."""

    name = "infrastructure.webserver_inventory"
    category = "infrastructure"
    severity = Severity.INFO
    description = "Detect installed web servers and their running status"
    target_types = {"app", "wordpress", "generic"}

    async def execute(self, client) -> list[AttackResult]:
        """Run web server inventory checks."""
        results = []

        results.append(await self._check_installed_webservers())
        results.append(await self._check_running_webservers())
        results.append(await self._check_port_ownership())

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

    async def _check_installed_webservers(self) -> AttackResult:
        """Check which web server packages are installed."""
        installed = {}

        for server_name, config in WEB_SERVERS.items():
            for package in config["packages"]:
                rc, out, _ = await self._run_cmd("dpkg", "-l", package)
                if rc == 0 and "ii  " + package in out:
                    # Package is installed
                    # Extract version from dpkg output
                    for line in out.splitlines():
                        if line.startswith("ii  " + package):
                            parts = line.split()
                            version = parts[2] if len(parts) >= 3 else "unknown"
                            if server_name not in installed:
                                installed[server_name] = []
                            installed[server_name].append({
                                "package": package,
                                "version": version,
                            })
                            break

        if not installed:
            return self._make_result(
                variant="installed_webservers",
                status=Status.DEFENDED,
                evidence="No web server packages detected",
                details="No known web server packages (nginx, apache2, lighttpd, caddy) are installed.",
                response={"installed": {}},
            )

        if len(installed) > 1:
            server_list = ", ".join(installed.keys())
            return self._make_result(
                variant="installed_webservers",
                status=Status.PARTIAL,
                severity=Severity.LOW,
                evidence=f"{len(installed)} web servers installed: {server_list}",
                details=(
                    f"Multiple web servers are installed: {server_list}. "
                    "This can lead to configuration confusion. Ensure only one is running "
                    "and consider removing unused packages."
                ),
                response={"installed": installed, "count": len(installed)},
            )

        server_name = list(installed.keys())[0]
        packages = [p["package"] for p in installed[server_name]]
        return self._make_result(
            variant="installed_webservers",
            status=Status.DEFENDED,
            evidence=f"{server_name} installed ({', '.join(packages)})",
            details=f"Web server: {server_name}",
            response={"installed": installed},
        )

    async def _check_running_webservers(self) -> AttackResult:
        """Check which web servers are running via systemd."""
        running = {}
        inactive = {}

        for server_name, config in WEB_SERVERS.items():
            service = config["service"]
            rc, out, _ = await self._run_cmd("systemctl", "is-active", service)

            if rc == 0 and out.strip() == "active":
                running[server_name] = {"service": service, "status": "active"}
            else:
                # Check if service exists but inactive
                rc2, out2, _ = await self._run_cmd("systemctl", "status", service)
                if rc2 in (0, 3):  # 0 = running, 3 = stopped
                    inactive[server_name] = {"service": service, "status": out.strip()}

        if not running and not inactive:
            return self._make_result(
                variant="running_webservers",
                status=Status.DEFENDED,
                evidence="No web server services detected",
                details="No web server systemd services found.",
                response={"running": {}, "inactive": {}},
            )

        if len(running) > 1:
            server_list = ", ".join(running.keys())
            return self._make_result(
                variant="running_webservers",
                status=Status.VULNERABLE,
                severity=Severity.MEDIUM,
                evidence=f"{len(running)} web servers running: {server_list}",
                details=(
                    f"Multiple web servers are running simultaneously: {server_list}. "
                    "This creates port conflicts and configuration issues. "
                    "Only one web server should be active."
                ),
                response={"running": running, "inactive": inactive},
            )

        if running:
            server_name = list(running.keys())[0]
            inactive_list = ", ".join(inactive.keys()) if inactive else "none"
            return self._make_result(
                variant="running_webservers",
                status=Status.DEFENDED,
                evidence=f"{server_name} active (inactive: {inactive_list})",
                details=f"Web server {server_name} is running. Inactive: {inactive_list}",
                response={"running": running, "inactive": inactive},
            )

        # No running servers but some inactive
        inactive_list = ", ".join(inactive.keys())
        return self._make_result(
            variant="running_webservers",
            status=Status.DEFENDED,
            evidence=f"Web servers installed but not running: {inactive_list}",
            details="Web server packages detected but no services are active.",
            response={"running": {}, "inactive": inactive},
        )

    async def _check_port_ownership(self) -> AttackResult:
        """Check which process owns ports 80 and 443."""
        port_owners = {}

        for port in ["80", "443"]:
            rc, out, _ = await self._run_cmd("sudo", "lsof", "-i", f":{port}", "-sTCP:LISTEN")
            if rc == 0 and out.strip():
                for line in out.splitlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 1:
                        process = parts[0]
                        if port not in port_owners:
                            port_owners[port] = []
                        port_owners[port].append(process)

        if not port_owners:
            return self._make_result(
                variant="port_ownership",
                status=Status.DEFENDED,
                evidence="Ports 80/443 not listening",
                details="No process is listening on HTTP (80) or HTTPS (443) ports.",
                response={"port_80": None, "port_443": None},
            )

        evidence_parts = []
        for port, processes in port_owners.items():
            unique = list(set(processes))
            evidence_parts.append(f"Port {port}: {', '.join(unique)}")

        return self._make_result(
            variant="port_ownership",
            status=Status.DEFENDED,
            evidence="; ".join(evidence_parts),
            details="Web server ports are active and owned by specific processes.",
            response=port_owners,
        )
