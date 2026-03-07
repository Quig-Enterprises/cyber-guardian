"""IAM Policy Review - audits IAM users for MFA, access key age, and root key presence."""

import asyncio
import json
import shutil
from datetime import datetime, timezone

from redteam.base import Attack, AttackResult, Severity, Status


class IAMAuditAttack(Attack):
    name = "cloud.iam_audit"
    category = "cloud"
    severity = Severity.HIGH
    description = "Audit IAM configuration for MFA gaps, stale access keys, and root account key exposure"
    target_types = {"app", "wordpress", "generic"}

    async def _run_aws(self, *args) -> tuple[int, str, str]:
        """Run an aws CLI command and return (returncode, stdout, stderr)."""
        aws = shutil.which("aws")
        proc = await asyncio.create_subprocess_exec(
            aws, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    async def execute(self, client) -> list[AttackResult]:
        results = []

        aws = shutil.which("aws")
        if not aws:
            skip_msg = "aws CLI not found in PATH. Install the AWS CLI to enable IAM auditing: https://aws.amazon.com/cli/"
            return [
                self._make_result(variant="mfa_disabled", status=Status.SKIPPED,
                                  evidence="aws CLI not found", details=skip_msg),
                self._make_result(variant="access_key_age", status=Status.SKIPPED,
                                  evidence="aws CLI not found", details=skip_msg),
                self._make_result(variant="root_access_keys", status=Status.SKIPPED,
                                  evidence="aws CLI not found", details=skip_msg),
            ]

        # Check credentials by listing users
        rc, stdout, stderr = await self._run_aws("iam", "list-users", "--output", "json")
        if rc != 0:
            skip_detail = (
                "Unable to list IAM users. Ensure AWS credentials are configured "
                "(run `aws configure` or set AWS_PROFILE / AWS_ACCESS_KEY_ID env vars).\n"
                f"Error: {stderr[:300]}"
            )
            return [
                self._make_result(variant="mfa_disabled", status=Status.SKIPPED,
                                  evidence=stderr[:500], details=skip_detail),
                self._make_result(variant="access_key_age", status=Status.SKIPPED,
                                  evidence=stderr[:500], details=skip_detail),
                self._make_result(variant="root_access_keys", status=Status.SKIPPED,
                                  evidence=stderr[:500], details=skip_detail),
            ]

        try:
            user_data = json.loads(stdout)
        except json.JSONDecodeError:
            return [self._make_result(
                variant="mfa_disabled",
                status=Status.ERROR,
                evidence=stdout[:300],
                details="Failed to parse aws iam list-users JSON output.",
            )]

        all_users = [u["UserName"] for u in user_data.get("Users", [])]
        # Limit to first 50 users in AWS mode
        users = all_users[:50]

        # --- Variant 1: mfa_disabled ---
        no_mfa = []
        checked_mfa = 0
        for username in users:
            rc2, out2, _ = await self._run_aws(
                "iam", "list-mfa-devices", "--user-name", username, "--output", "json"
            )
            if rc2 == 0:
                try:
                    mfa_data = json.loads(out2)
                    if not mfa_data.get("MFADevices"):
                        no_mfa.append(username)
                except json.JSONDecodeError:
                    pass
            checked_mfa += 1

        if no_mfa:
            results.append(self._make_result(
                variant="mfa_disabled",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="\n".join(no_mfa[:20]),
                details=(
                    f"{len(no_mfa)} of {checked_mfa} IAM users have no MFA device configured. "
                    f"Users: {', '.join(no_mfa[:10])}. "
                    "Without MFA, compromised credentials grant full account access."
                ),
                request={"command": "aws iam list-mfa-devices", "users_checked": checked_mfa},
                response={"no_mfa_users": len(no_mfa), "total_users": len(all_users)},
            ))
        else:
            results.append(self._make_result(
                variant="mfa_disabled",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"All {checked_mfa} checked IAM users have MFA configured.",
                details=f"Checked {checked_mfa} of {len(all_users)} total users.",
                request={"command": "aws iam list-mfa-devices", "users_checked": checked_mfa},
                response={"no_mfa_users": 0, "total_users": len(all_users)},
            ))

        # --- Variant 2: access_key_age ---
        old_keys = []
        checked_keys = 0
        now = datetime.now(timezone.utc)
        max_key_age_days = 90

        for username in users:
            rc2, out2, _ = await self._run_aws(
                "iam", "list-access-keys", "--user-name", username, "--output", "json"
            )
            if rc2 == 0:
                try:
                    key_data = json.loads(out2)
                    for key in key_data.get("AccessKeyMetadata", []):
                        if key.get("Status") != "Active":
                            continue
                        create_date_str = key.get("CreateDate", "")
                        if not create_date_str:
                            continue
                        # ISO 8601 with trailing Z or +00:00
                        create_date_str = create_date_str.replace("Z", "+00:00")
                        try:
                            create_date = datetime.fromisoformat(create_date_str)
                        except ValueError:
                            continue
                        age_days = (now - create_date).days
                        if age_days > max_key_age_days:
                            old_keys.append((username, key.get("AccessKeyId", "?"), age_days))
                except json.JSONDecodeError:
                    pass
            checked_keys += 1

        if old_keys:
            evidence_lines = [f"{u}: key {kid} is {days} days old" for u, kid, days in old_keys]
            results.append(self._make_result(
                variant="access_key_age",
                status=Status.VULNERABLE,
                severity=Severity.MEDIUM,
                evidence="\n".join(evidence_lines[:20]),
                details=(
                    f"{len(old_keys)} active access key(s) are older than {max_key_age_days} days. "
                    "Rotate access keys regularly to limit exposure from credential leaks."
                ),
                request={"command": "aws iam list-access-keys", "users_checked": checked_keys,
                         "max_key_age_days": max_key_age_days},
                response={"stale_keys": len(old_keys), "total_users_checked": checked_keys},
            ))
        else:
            results.append(self._make_result(
                variant="access_key_age",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"All active access keys for {checked_keys} checked users are within {max_key_age_days} days.",
                details=f"Checked {checked_keys} of {len(all_users)} total users.",
                request={"command": "aws iam list-access-keys", "users_checked": checked_keys},
                response={"stale_keys": 0, "total_users_checked": checked_keys},
            ))

        # --- Variant 3: root_access_keys ---
        rc3, out3, err3 = await self._run_aws("iam", "get-account-summary", "--output", "json")
        if rc3 != 0:
            results.append(self._make_result(
                variant="root_access_keys",
                status=Status.SKIPPED,
                evidence=err3[:300],
                details=(
                    "Unable to retrieve account summary. This check requires iam:GetAccountSummary permission. "
                    f"Error: {err3[:200]}"
                ),
            ))
        else:
            try:
                summary = json.loads(out3).get("SummaryMap", {})
                root_keys_present = summary.get("AccountAccessKeysPresent", 0)
                if root_keys_present > 0:
                    results.append(self._make_result(
                        variant="root_access_keys",
                        status=Status.VULNERABLE,
                        severity=Severity.CRITICAL,
                        evidence=f"AccountAccessKeysPresent={root_keys_present}",
                        details=(
                            "The AWS root account has active access keys. This is a critical security risk. "
                            "Root access keys should be deleted immediately; use IAM roles instead."
                        ),
                        request={"command": "aws iam get-account-summary"},
                        response={"AccountAccessKeysPresent": root_keys_present},
                    ))
                else:
                    results.append(self._make_result(
                        variant="root_access_keys",
                        status=Status.DEFENDED,
                        severity=Severity.INFO,
                        evidence="AccountAccessKeysPresent=0",
                        details="Root account has no active access keys (best practice).",
                        request={"command": "aws iam get-account-summary"},
                        response={"AccountAccessKeysPresent": 0},
                    ))
            except json.JSONDecodeError:
                results.append(self._make_result(
                    variant="root_access_keys",
                    status=Status.ERROR,
                    evidence=out3[:300],
                    details="Failed to parse aws iam get-account-summary JSON output.",
                ))

        return results
