"""Dependency manifest CVE lookup attack module."""

import json
import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status
from redteam.cve.engine import CVEEngine
from redteam.cve.models import CVEQuery

logger = logging.getLogger(__name__)

# Manifest paths to probe and their ecosystems
MANIFEST_PROBES = [
    ("/package.json", "npm"),
    ("/composer.json", "packagist"),
    ("/requirements.txt", "pypi"),
    ("/Gemfile.lock", "rubygems"),
]

# Regex for requirements.txt lines: package==version or package>=version
REQUIREMENTS_RE = re.compile(r"^([\w._-]+)\s*[=><!]+\s*([\d.]+)", re.MULTILINE)


class DependencyCVEAttack(Attack):
    """Known CVE lookup for exposed dependency manifests."""

    name = "cve.dependency_cve"
    category = "cve"
    severity = Severity.MEDIUM
    description = "Known CVE lookup for exposed dependency manifests"
    target_types = {"generic", "app"}

    async def execute(self, client) -> list[AttackResult]:
        results: list[AttackResult] = []

        engine = CVEEngine(self._config)
        found_any_manifest = False

        for path, ecosystem in MANIFEST_PROBES:
            start = time.monotonic()

            try:
                status, body, headers = await client.get(path, cookies={})
            except Exception as exc:
                logger.debug("Could not probe %s: %s", path, exc)
                continue

            if status != 200 or not body.strip():
                continue

            # Try to parse manifest content
            deps = self._parse_manifest(path, body, ecosystem)
            if deps is None:
                continue

            found_any_manifest = True

            # Information disclosure finding: manifest is publicly accessible
            results.append(self._make_result(
                variant=f"manifest{path}",
                status=Status.VULNERABLE,
                severity=Severity.MEDIUM,
                evidence=f"Dependency manifest {path} is publicly accessible",
                details=(
                    f"HTTP {status} returned for {path} with {len(deps)} dependencies. "
                    f"Publicly accessible dependency manifests reveal the technology "
                    f"stack and specific versions, enabling targeted CVE exploitation."
                ),
                request={"method": "GET", "path": path},
                response={"status": status, "body": body[:500]},
                duration_ms=(time.monotonic() - start) * 1000,
            ))

            # Query CVEs for each dependency
            for dep_name, dep_version in deps:
                dep_start = time.monotonic()

                try:
                    query = CVEQuery(
                        software=dep_name,
                        version=dep_version,
                        ecosystem=ecosystem,
                        max_results=10,
                    )
                    cves = await engine.lookup(query)
                except Exception as exc:
                    logger.debug("CVE lookup failed for %s/%s: %s",
                                 dep_name, dep_version, exc)
                    continue

                for cve in cves:
                    risk = cve.risk_score
                    if risk >= 4.0:
                        status_val = Status.VULNERABLE
                    else:
                        status_val = Status.PARTIAL

                    sev = self._cvss_to_severity(cve.cvss_v31_score)
                    kev_info = " [CISA KEV]" if cve.in_kev else ""

                    results.append(self._make_result(
                        variant=f"dep/{dep_name}/{cve.cve_id}",
                        status=status_val,
                        severity=sev,
                        evidence=(
                            f"{cve.cve_id} in {dep_name}@{dep_version} "
                            f"(CVSS {cve.cvss_v31_score or 'N/A'}, "
                            f"risk {risk:.1f}){kev_info}"
                        ),
                        details=(
                            f"Dependency {dep_name} {dep_version} "
                            f"(from {path}): {cve.description[:250]}"
                            f"{' Fixed in: ' + cve.fixed_version if cve.fixed_version else ''}"
                        ),
                        duration_ms=(time.monotonic() - dep_start) * 1000,
                    ))

        if not found_any_manifest:
            results.append(self._make_result(
                variant="dependency/no_manifests",
                status=Status.DEFENDED,
                evidence="No dependency manifests exposed",
                details="Probed package.json, composer.json, requirements.txt, "
                        "and Gemfile.lock — none are publicly accessible.",
            ))

        return results

    @staticmethod
    def _parse_manifest(path: str, body: str, ecosystem: str):
        """Parse dependency manifest and return list of (name, version) tuples.

        Returns None if the content doesn't look like a valid manifest.
        """
        deps: list[tuple[str, str]] = []

        if path == "/package.json":
            try:
                data = json.loads(body)
                if not isinstance(data, dict):
                    return None
                for section in ("dependencies", "devDependencies"):
                    section_deps = data.get(section, {})
                    if isinstance(section_deps, dict):
                        for name, version_spec in section_deps.items():
                            version = _extract_semver(str(version_spec))
                            if version:
                                deps.append((name, version))
                return deps if deps or "name" in data else None
            except (json.JSONDecodeError, ValueError):
                return None

        elif path == "/composer.json":
            try:
                data = json.loads(body)
                if not isinstance(data, dict):
                    return None
                for section in ("require", "require-dev"):
                    section_deps = data.get(section, {})
                    if isinstance(section_deps, dict):
                        for name, version_spec in section_deps.items():
                            if name == "php" or name.startswith("ext-"):
                                continue
                            version = _extract_semver(str(version_spec))
                            if version:
                                deps.append((name, version))
                return deps if deps or "name" in data else None
            except (json.JSONDecodeError, ValueError):
                return None

        elif path == "/requirements.txt":
            matches = REQUIREMENTS_RE.findall(body)
            for name, version in matches:
                deps.append((name, version))
            # Only return if it looks like a real requirements file
            return deps if deps else None

        elif path == "/Gemfile.lock":
            # Simple parser for Gemfile.lock GEM specs section
            in_specs = False
            for line in body.splitlines():
                stripped = line.strip()
                if stripped == "specs:":
                    in_specs = True
                    continue
                if in_specs and stripped and not stripped.startswith("("):
                    # Lines like "    rails (7.0.4)"
                    gem_match = re.match(r"([\w._-]+)\s+\(([\d.]+)", stripped)
                    if gem_match:
                        deps.append((gem_match.group(1), gem_match.group(2)))
                elif in_specs and not line.startswith(" "):
                    in_specs = False
            return deps if deps else None

        return None

    @staticmethod
    def _cvss_to_severity(score) -> Severity:
        """Map CVSS score to Severity enum."""
        if score is None:
            return Severity.MEDIUM
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW


def _extract_semver(version_spec: str) -> str:
    """Extract a clean semver from a version specifier.

    Examples:
        "^1.2.3" -> "1.2.3"
        "~2.0" -> "2.0"
        ">=3.1.0 <4.0.0" -> "3.1.0"
        "1.0.0" -> "1.0.0"
    """
    match = re.search(r"(\d+(?:\.\d+)*)", version_spec)
    return match.group(1) if match else ""
