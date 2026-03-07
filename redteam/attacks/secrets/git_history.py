"""Git history secret leakage attack module.

Tests for exposed .git directories over HTTP, and scans local git history
for deleted secret files or commits that added/removed password-bearing content.

Evaluation:
- /.git/HEAD or /.git/config accessible via HTTP -> CRITICAL (VULNERABLE)
- git log finds deleted .env/.key/.pem files with secret content -> VULNERABLE
- git grep finds 'password' in historical commits -> VULNERABLE
- No exposure found -> DEFENDED
- No source_path and HTTP checks clean -> DEFENDED
"""

import asyncio
import subprocess
import time
import logging
from pathlib import Path

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Max commits to scan in full mode; reduced in AWS mode for safety
GIT_LOG_MAX_COMMITS_FULL = 50
GIT_LOG_MAX_COMMITS_AWS = 20


class GitHistoryScanAttack(Attack):
    """Scan for git directory exposure and secrets leaked in git history."""

    name = "secrets.git_history"
    category = "secrets"
    severity = Severity.HIGH
    description = "Detect exposed .git directories and secrets leaked in git commit history"
    target_types = {"app", "wordpress", "generic", "static"}

    def _get_source_path(self) -> Path | None:
        """Return the configured source path if it exists."""
        sp = self._config.get("target", {}).get("source_path")
        if not sp:
            return None
        p = Path(sp)
        return p if p.exists() else None

    def _max_commits(self) -> int:
        """Return the commit scan limit based on execution mode."""
        return GIT_LOG_MAX_COMMITS_AWS if self._is_aws_mode() else GIT_LOG_MAX_COMMITS_FULL

    def _run_git(self, args: list[str], cwd: Path, timeout: int = 30) -> tuple[int, str, str]:
        """Run a git command and return (returncode, stdout, stderr)."""
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "git command timed out"
        except FileNotFoundError:
            return -1, "", "git not found in PATH"
        except Exception as e:
            return -1, "", str(e)

    async def execute(self, client) -> list[AttackResult]:
        results = []
        results.append(await self._probe_git_directory_web(client))
        results.append(await self._scan_git_log_secrets())
        results.append(await self._scan_git_grep_secrets())
        return results

    async def _probe_git_directory_web(self, client) -> AttackResult:
        """Check if /.git directory is accessible over HTTP."""
        start = time.monotonic()

        probe_paths = [
            ("/.git/HEAD", "ref: ", "Git HEAD file exposed — full repository may be downloadable"),
            ("/.git/config", "[core]", "Git config file exposed — repository metadata leaked"),
        ]

        try:
            for path, indicator, detail_msg in probe_paths:
                status_code, body, headers = await client.get(path, cookies={})

                if status_code == 200 and indicator in body:
                    duration = (time.monotonic() - start) * 1000
                    return self._make_result(
                        variant="git_directory_web",
                        status=Status.VULNERABLE,
                        severity=Severity.CRITICAL,
                        evidence=(
                            f"{path} returned HTTP 200 containing '{indicator}'. "
                            "The .git directory is publicly accessible."
                        ),
                        details=(
                            f"{detail_msg}. An attacker can reconstruct the entire repository "
                            "using tools like git-dumper, exposing all source code and any "
                            "secrets ever committed."
                        ),
                        request={"path": path, "method": "GET"},
                        response={"status": status_code, "body_preview": body[:300]},
                        duration_ms=duration,
                    )

                await asyncio.sleep(0.1)

            return self._make_result(
                variant="git_directory_web",
                status=Status.DEFENDED,
                evidence="/.git/HEAD and /.git/config are not accessible over HTTP",
                details="Git directory is not served publicly (correct configuration)",
                request={"paths_tested": [p for p, _, _ in probe_paths]},
                duration_ms=(time.monotonic() - start) * 1000,
            )

        except Exception as e:
            return self._make_result(
                variant="git_directory_web",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _scan_git_log_secrets(self) -> AttackResult:
        """Scan git log for deleted secret files (.env, .key, .pem)."""
        start = time.monotonic()
        source_path = self._get_source_path()

        if source_path is None:
            return self._make_result(
                variant="git_log_secrets",
                status=Status.SKIPPED,
                evidence="No source_path configured — cannot scan git history",
                details="Set target.source_path to enable git history scanning",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        # Check if path is a git repository
        rc, stdout, stderr = self._run_git(["rev-parse", "--git-dir"], source_path)
        if rc != 0:
            return self._make_result(
                variant="git_log_secrets",
                status=Status.SKIPPED,
                evidence=f"source_path is not a git repository: {stderr.strip()}",
                details=str(source_path),
                duration_ms=(time.monotonic() - start) * 1000,
            )

        max_commits = self._max_commits()

        # Find commits that deleted secret-looking files
        rc, stdout, stderr = self._run_git(
            [
                "log", "--all", f"-{max_commits}", "-p",
                "--diff-filter=D",
                "--", "*.env", "*.key", "*.pem", "*.p12", "*.pfx", "id_rsa", "id_ed25519",
            ],
            source_path,
            timeout=60,
        )

        duration = (time.monotonic() - start) * 1000

        if rc != 0:
            return self._make_result(
                variant="git_log_secrets",
                status=Status.ERROR,
                details=f"git log failed: {stderr.strip()}",
                duration_ms=duration,
            )

        if stdout.strip():
            # Extract commit hashes and file names from the log output
            findings = []
            for line in stdout.splitlines():
                if line.startswith("commit "):
                    findings.append(line.strip())
                elif line.startswith("diff --git"):
                    findings.append(line.strip())
                if len(findings) >= 20:
                    break

            return self._make_result(
                variant="git_log_secrets",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="\n".join(findings[:20]),
                details=(
                    f"Git history contains commits that deleted secret files (.env, .key, .pem). "
                    f"Scanned last {max_commits} commits. These files' contents remain in git history "
                    "and can be retrieved by anyone with repository access."
                ),
                request={"source_path": str(source_path), "max_commits": max_commits},
                response={"log_lines": len(stdout.splitlines())},
                duration_ms=duration,
            )

        return self._make_result(
            variant="git_log_secrets",
            status=Status.DEFENDED,
            evidence=f"No deleted secret files found in last {max_commits} commits",
            details="Scanned for deleted *.env, *.key, *.pem, *.p12, *.pfx, id_rsa, id_ed25519 files",
            request={"source_path": str(source_path), "max_commits": max_commits},
            duration_ms=duration,
        )

    async def _scan_git_grep_secrets(self) -> AttackResult:
        """Search git history for commits that added/removed password-bearing content."""
        start = time.monotonic()
        source_path = self._get_source_path()

        if source_path is None:
            return self._make_result(
                variant="git_grep_secrets",
                status=Status.SKIPPED,
                evidence="No source_path configured — cannot scan git history",
                details="Set target.source_path to enable git history scanning",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        # Verify it's a git repo
        rc, stdout, stderr = self._run_git(["rev-parse", "--git-dir"], source_path)
        if rc != 0:
            return self._make_result(
                variant="git_grep_secrets",
                status=Status.SKIPPED,
                evidence=f"source_path is not a git repository: {stderr.strip()}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        max_commits = self._max_commits()

        # Use git log -S (pickaxe) to find commits that introduced/removed 'password'
        rc, stdout, stderr = self._run_git(
            [
                "-C", str(source_path),
                "log", "-p", "--all", f"-{max_commits}",
                "-S", "password",
                "--",
            ],
            source_path,
            timeout=60,
        )

        duration = (time.monotonic() - start) * 1000

        if rc != 0:
            return self._make_result(
                variant="git_grep_secrets",
                status=Status.ERROR,
                details=f"git log -S failed: {stderr.strip()}",
                duration_ms=duration,
            )

        if stdout.strip():
            # Summarize which commits and files were flagged
            findings = []
            for line in stdout.splitlines():
                if line.startswith("commit ") or line.startswith("+password") or line.startswith("-password"):
                    findings.append(line.strip())
                if len(findings) >= 15:
                    break

            return self._make_result(
                variant="git_grep_secrets",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="\n".join(findings[:15]),
                details=(
                    f"Found {len([l for l in stdout.splitlines() if l.startswith('commit ')])} commit(s) "
                    f"containing 'password' changes in last {max_commits} commits. "
                    "Review these commits to ensure no credentials were hardcoded then removed."
                ),
                request={"source_path": str(source_path), "search_term": "password", "max_commits": max_commits},
                response={"log_lines": len(stdout.splitlines())},
                duration_ms=duration,
            )

        return self._make_result(
            variant="git_grep_secrets",
            status=Status.DEFENDED,
            evidence=f"No 'password' string changes found in last {max_commits} commits",
            details="Used git log -S 'password' to search for commits adding or removing password strings",
            request={"source_path": str(source_path), "max_commits": max_commits},
            duration_ms=duration,
        )
