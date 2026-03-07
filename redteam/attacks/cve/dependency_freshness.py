"""Detect outdated and end-of-life dependencies beyond CVE checks.

Inspects package manager lock/manifest files on the local filesystem
(via source_path config) or via HTTP response headers to detect outdated
dependencies that may not yet have known CVEs but still represent risk.

Evaluation:
- Package is a major version behind -> VULNERABLE
- Package is a minor version behind -> PARTIAL
- Unpinned Python dependency -> PARTIAL
- PHP version is end-of-life -> VULNERABLE
- All dependencies are current -> DEFENDED
"""

import json
import re
import subprocess
import time
import logging
from pathlib import Path

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# PHP versions and their EOL dates (approximate, YYYY-MM format)
# Versions before 8.1 are EOL as of 2024
PHP_EOL_VERSIONS = {
    "5.": True,
    "7.0": True,
    "7.1": True,
    "7.2": True,
    "7.3": True,
    "7.4": True,
    "8.0": True,
}

# PHP version regex for headers
PHP_VERSION_RE = re.compile(r"PHP/([\d.]+)", re.IGNORECASE)


class DependencyFreshnessAttack(Attack):
    """Detect outdated and end-of-life dependencies."""

    name = "cve.dependency_freshness"
    category = "cve"
    severity = Severity.MEDIUM
    description = "Detect outdated and end-of-life dependencies beyond CVE checks"
    target_types = {"app", "wordpress", "generic", "static"}

    def _get_source_path(self) -> str | None:
        """Return the source_path from config, if available."""
        return self._config.get("target", {}).get("source_path")

    async def execute(self, client) -> list[AttackResult]:
        """Run all dependency freshness variants."""
        results = []
        source_path = self._get_source_path()

        results.append(await self._check_npm_outdated(source_path))
        results.append(await self._check_composer_outdated(source_path))
        results.append(await self._check_python_outdated(source_path))
        results.append(await self._check_php_version(client, source_path))

        return results

    async def _check_npm_outdated(self, source_path: str | None) -> AttackResult:
        """npm_outdated: Check for outdated npm packages via package.json."""
        start = time.monotonic()

        if not source_path:
            return self._make_result(
                variant="npm_outdated",
                status=Status.SKIPPED,
                details="No source_path configured - cannot check npm packages",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        package_json_path = Path(source_path) / "package.json"
        if not package_json_path.is_file():
            return self._make_result(
                variant="npm_outdated",
                status=Status.SKIPPED,
                details=f"No package.json found at {package_json_path}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        # In AWS mode, only read files - don't run npm commands
        if self._is_aws_mode():
            return self._check_npm_from_file(package_json_path, start)

        try:
            proc = subprocess.run(
                ["npm", "outdated", "--json"],
                cwd=source_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            # npm outdated exits with code 1 when there are outdated packages
            output = proc.stdout.strip()
            if not output:
                return self._make_result(
                    variant="npm_outdated",
                    status=Status.DEFENDED,
                    evidence="All npm packages are up to date",
                    details="npm outdated reported no outdated packages",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            try:
                outdated = json.loads(output)
            except json.JSONDecodeError:
                return self._make_result(
                    variant="npm_outdated",
                    status=Status.ERROR,
                    details=f"Failed to parse npm outdated output: {output[:200]}",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            major_behind = []
            minor_behind = []

            for pkg_name, info in outdated.items():
                current = info.get("current", "")
                latest = info.get("latest", "")
                if not current or not latest:
                    continue

                current_parts = current.split(".")
                latest_parts = latest.split(".")

                try:
                    if int(latest_parts[0]) > int(current_parts[0]):
                        major_behind.append(f"{pkg_name}: {current} -> {latest}")
                    elif (len(latest_parts) > 1 and len(current_parts) > 1 and
                          int(latest_parts[1]) > int(current_parts[1])):
                        minor_behind.append(f"{pkg_name}: {current} -> {latest}")
                except (ValueError, IndexError):
                    continue

            duration = (time.monotonic() - start) * 1000

            if major_behind:
                return self._make_result(
                    variant="npm_outdated",
                    status=Status.VULNERABLE,
                    evidence=f"{len(major_behind)} packages are a major version behind",
                    details=(
                        f"Major version outdated: {'; '.join(major_behind[:5])}"
                        f"{f' (+{len(major_behind)-5} more)' if len(major_behind) > 5 else ''}"
                        f"{f'. Minor version outdated: {len(minor_behind)} packages' if minor_behind else ''}"
                    ),
                    request={"source_path": source_path},
                    response={"major_behind": major_behind[:10],
                              "minor_behind": minor_behind[:10],
                              "total_outdated": len(outdated)},
                    duration_ms=duration,
                )
            elif minor_behind:
                return self._make_result(
                    variant="npm_outdated",
                    status=Status.PARTIAL,
                    evidence=f"{len(minor_behind)} packages are a minor version behind",
                    details=(
                        f"Minor version outdated: {'; '.join(minor_behind[:5])}"
                        f"{f' (+{len(minor_behind)-5} more)' if len(minor_behind) > 5 else ''}"
                    ),
                    request={"source_path": source_path},
                    response={"minor_behind": minor_behind[:10],
                              "total_outdated": len(outdated)},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="npm_outdated",
                    status=Status.DEFENDED,
                    evidence="npm packages are reasonably current",
                    details=f"Checked {len(outdated)} packages - none significantly outdated",
                    duration_ms=duration,
                )

        except FileNotFoundError:
            return self._make_result(
                variant="npm_outdated",
                status=Status.SKIPPED,
                details="npm command not available on this system",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except subprocess.TimeoutExpired:
            return self._make_result(
                variant="npm_outdated",
                status=Status.ERROR,
                details="npm outdated timed out after 60 seconds",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            return self._make_result(
                variant="npm_outdated",
                status=Status.ERROR,
                details=f"Error running npm outdated: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    def _check_npm_from_file(self, package_json_path: Path, start: float) -> AttackResult:
        """Fallback: parse package.json directly when npm is unavailable or in AWS mode."""
        try:
            data = json.loads(package_json_path.read_text())
            all_deps = {}
            for section in ("dependencies", "devDependencies"):
                all_deps.update(data.get(section, {}))

            if not all_deps:
                return self._make_result(
                    variant="npm_outdated",
                    status=Status.DEFENDED,
                    evidence="No dependencies listed in package.json",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            return self._make_result(
                variant="npm_outdated",
                status=Status.SKIPPED,
                details=(
                    f"Found {len(all_deps)} dependencies in package.json but cannot "
                    f"run 'npm outdated' (AWS mode or npm unavailable). "
                    f"Manual review recommended."
                ),
                request={"file": str(package_json_path)},
                response={"total_deps": len(all_deps)},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            return self._make_result(
                variant="npm_outdated",
                status=Status.ERROR,
                details=f"Failed to parse package.json: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _check_composer_outdated(self, source_path: str | None) -> AttackResult:
        """composer_outdated: Check for outdated Composer packages."""
        start = time.monotonic()

        if not source_path:
            return self._make_result(
                variant="composer_outdated",
                status=Status.SKIPPED,
                details="No source_path configured - cannot check Composer packages",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        composer_json_path = Path(source_path) / "composer.json"
        composer_lock_path = Path(source_path) / "composer.lock"

        if not composer_json_path.is_file():
            return self._make_result(
                variant="composer_outdated",
                status=Status.SKIPPED,
                details=f"No composer.json found at {composer_json_path}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        # If AWS mode or composer not available, parse lock file
        if self._is_aws_mode() or not self._command_available("composer"):
            return self._check_composer_from_lock(
                composer_json_path, composer_lock_path, start
            )

        try:
            proc = subprocess.run(
                ["composer", "outdated", "--format=json", "--no-interaction"],
                cwd=source_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

            output = proc.stdout.strip()
            if not output:
                return self._make_result(
                    variant="composer_outdated",
                    status=Status.DEFENDED,
                    evidence="All Composer packages are up to date",
                    details="composer outdated reported no outdated packages",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            try:
                result = json.loads(output)
                installed = result.get("installed", [])
            except json.JSONDecodeError:
                return self._make_result(
                    variant="composer_outdated",
                    status=Status.ERROR,
                    details=f"Failed to parse composer outdated output: {output[:200]}",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            major_behind = []
            minor_behind = []

            for pkg in installed:
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v")
                latest = pkg.get("latest", "").lstrip("v")
                if not version or not latest:
                    continue

                v_parts = version.split(".")
                l_parts = latest.split(".")
                try:
                    if int(l_parts[0]) > int(v_parts[0]):
                        major_behind.append(f"{name}: {version} -> {latest}")
                    elif (len(l_parts) > 1 and len(v_parts) > 1 and
                          int(l_parts[1]) > int(v_parts[1])):
                        minor_behind.append(f"{name}: {version} -> {latest}")
                except (ValueError, IndexError):
                    continue

            duration = (time.monotonic() - start) * 1000

            if major_behind:
                return self._make_result(
                    variant="composer_outdated",
                    status=Status.VULNERABLE,
                    evidence=f"{len(major_behind)} Composer packages are a major version behind",
                    details=(
                        f"Major: {'; '.join(major_behind[:5])}"
                        f"{f' (+{len(major_behind)-5} more)' if len(major_behind) > 5 else ''}"
                    ),
                    request={"source_path": source_path},
                    response={"major_behind": major_behind[:10],
                              "minor_behind": minor_behind[:10]},
                    duration_ms=duration,
                )
            elif minor_behind:
                return self._make_result(
                    variant="composer_outdated",
                    status=Status.PARTIAL,
                    evidence=f"{len(minor_behind)} Composer packages are a minor version behind",
                    details=f"Minor: {'; '.join(minor_behind[:5])}",
                    request={"source_path": source_path},
                    response={"minor_behind": minor_behind[:10]},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="composer_outdated",
                    status=Status.DEFENDED,
                    evidence="Composer packages are reasonably current",
                    duration_ms=duration,
                )

        except FileNotFoundError:
            return self._check_composer_from_lock(
                composer_json_path, composer_lock_path, start
            )
        except subprocess.TimeoutExpired:
            return self._make_result(
                variant="composer_outdated",
                status=Status.ERROR,
                details="composer outdated timed out after 120 seconds",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            return self._make_result(
                variant="composer_outdated",
                status=Status.ERROR,
                details=f"Error running composer outdated: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    def _check_composer_from_lock(self, composer_json_path: Path,
                                  composer_lock_path: Path,
                                  start: float) -> AttackResult:
        """Fallback: parse composer.lock for version info."""
        if not composer_lock_path.is_file():
            try:
                data = json.loads(composer_json_path.read_text())
                deps = {}
                for section in ("require", "require-dev"):
                    deps.update(data.get(section, {}))
                dep_count = len([k for k in deps if k != "php" and not k.startswith("ext-")])
                return self._make_result(
                    variant="composer_outdated",
                    status=Status.SKIPPED,
                    details=(
                        f"Found {dep_count} dependencies in composer.json but no "
                        f"composer.lock file and composer command unavailable. "
                        f"Manual review recommended."
                    ),
                    duration_ms=(time.monotonic() - start) * 1000,
                )
            except Exception as e:
                return self._make_result(
                    variant="composer_outdated",
                    status=Status.ERROR,
                    details=f"Failed to parse composer.json: {e}",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

        try:
            lock_data = json.loads(composer_lock_path.read_text())
            packages = lock_data.get("packages", [])
            return self._make_result(
                variant="composer_outdated",
                status=Status.SKIPPED,
                details=(
                    f"Found {len(packages)} packages in composer.lock but cannot "
                    f"run 'composer outdated' to check versions. Manual review recommended."
                ),
                request={"file": str(composer_lock_path)},
                response={"total_packages": len(packages)},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            return self._make_result(
                variant="composer_outdated",
                status=Status.ERROR,
                details=f"Failed to parse composer.lock: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _check_python_outdated(self, source_path: str | None) -> AttackResult:
        """python_outdated: Check requirements.txt for unpinned or outdated deps."""
        start = time.monotonic()

        if not source_path:
            return self._make_result(
                variant="python_outdated",
                status=Status.SKIPPED,
                details="No source_path configured - cannot check Python dependencies",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        requirements_path = Path(source_path) / "requirements.txt"
        if not requirements_path.is_file():
            return self._make_result(
                variant="python_outdated",
                status=Status.SKIPPED,
                details=f"No requirements.txt found at {requirements_path}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        try:
            content = requirements_path.read_text()
            lines = [
                line.strip() for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
                and not line.strip().startswith("-")
            ]

            if not lines:
                return self._make_result(
                    variant="python_outdated",
                    status=Status.DEFENDED,
                    evidence="requirements.txt is empty",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            unpinned = []
            pinned = []

            for line in lines:
                # Remove comments
                line = line.split("#")[0].strip()
                if not line:
                    continue

                # Check for pinning operators
                if "==" in line:
                    pinned.append(line)
                elif ">=" in line or "<=" in line or "~=" in line or "!=" in line:
                    # Range constraint - better than nothing but not exact
                    pinned.append(line)
                else:
                    # No version constraint at all
                    unpinned.append(line)

            duration = (time.monotonic() - start) * 1000

            if unpinned:
                return self._make_result(
                    variant="python_outdated",
                    status=Status.PARTIAL,
                    evidence=f"{len(unpinned)}/{len(lines)} Python dependencies are unpinned",
                    details=(
                        f"Unpinned dependencies (no version constraint): "
                        f"{', '.join(unpinned[:10])}"
                        f"{f' (+{len(unpinned)-10} more)' if len(unpinned) > 10 else ''}. "
                        f"Unpinned deps may install different versions across environments."
                    ),
                    request={"file": str(requirements_path)},
                    response={"unpinned": unpinned[:20],
                              "pinned_count": len(pinned),
                              "total": len(lines)},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="python_outdated",
                    status=Status.DEFENDED,
                    evidence=f"All {len(pinned)} Python dependencies are version-pinned",
                    details="Every dependency in requirements.txt has a version constraint",
                    request={"file": str(requirements_path)},
                    response={"pinned_count": len(pinned), "total": len(lines)},
                    duration_ms=duration,
                )

        except Exception as e:
            return self._make_result(
                variant="python_outdated",
                status=Status.ERROR,
                details=f"Failed to parse requirements.txt: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _check_php_version(self, client, source_path: str | None) -> AttackResult:
        """php_version: Check PHP version from headers or local binary for EOL status."""
        start = time.monotonic()

        php_version = None

        # Method 1: Check HTTP response headers
        try:
            status_code, body, headers = await client.get("/", cookies={})
            x_powered = headers.get("X-Powered-By", "")
            server_header = headers.get("Server", "")

            for header_val in (x_powered, server_header):
                match = PHP_VERSION_RE.search(header_val)
                if match:
                    php_version = match.group(1)
                    break
        except Exception:
            pass

        # Method 2: Check local PHP binary (if source_path available)
        if php_version is None and source_path and not self._is_aws_mode():
            try:
                proc = subprocess.run(
                    ["php", "-v"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                match = PHP_VERSION_RE.search(proc.stdout)
                if match:
                    php_version = match.group(1)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        duration = (time.monotonic() - start) * 1000

        if php_version is None:
            return self._make_result(
                variant="php_version",
                status=Status.SKIPPED,
                details="Could not determine PHP version from headers or local binary",
                duration_ms=duration,
            )

        # Check if EOL
        is_eol = False
        for prefix, eol in PHP_EOL_VERSIONS.items():
            if php_version.startswith(prefix) and eol:
                is_eol = True
                break

        if is_eol:
            return self._make_result(
                variant="php_version",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"PHP {php_version} is end-of-life",
                details=(
                    f"PHP {php_version} no longer receives security patches. "
                    f"Upgrade to a supported PHP version (8.1+) immediately."
                ),
                request={"method": "header inspection"},
                response={"php_version": php_version, "eol": True},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="php_version",
                status=Status.DEFENDED,
                evidence=f"PHP {php_version} is a supported version",
                details=f"PHP {php_version} is within its support lifecycle",
                request={"method": "header inspection"},
                response={"php_version": php_version, "eol": False},
                duration_ms=duration,
            )

    @staticmethod
    def _command_available(cmd: str) -> bool:
        """Check if a command is available on the system."""
        try:
            subprocess.run(
                ["which", cmd],
                capture_output=True,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
