"""S3 Bucket Permission Audit - checks for public access, encryption, and logging gaps."""

import asyncio
import json
import shutil
from datetime import datetime, timezone

from redteam.base import Attack, AttackResult, Severity, Status


class S3BucketsAttack(Attack):
    name = "cloud.s3_buckets"
    category = "cloud"
    severity = Severity.CRITICAL
    description = "Audit S3 bucket permissions for public access, missing encryption, and disabled logging"
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
            return [self._make_result(
                variant="public_buckets",
                status=Status.SKIPPED,
                evidence="aws CLI not found in PATH",
                details="Install the AWS CLI to enable cloud security auditing: https://aws.amazon.com/cli/",
            ), self._make_result(
                variant="bucket_encryption",
                status=Status.SKIPPED,
                evidence="aws CLI not found in PATH",
                details="Install the AWS CLI to enable cloud security auditing.",
            ), self._make_result(
                variant="bucket_logging",
                status=Status.SKIPPED,
                evidence="aws CLI not found in PATH",
                details="Install the AWS CLI to enable cloud security auditing.",
            )]

        # List all buckets first
        rc, stdout, stderr = await self._run_aws("s3api", "list-buckets", "--output", "json")
        if rc != 0:
            skip_detail = (
                "Unable to list S3 buckets. Ensure AWS credentials are configured "
                "(run `aws configure` or set AWS_PROFILE / AWS_ACCESS_KEY_ID env vars).\n"
                f"Error: {stderr[:300]}"
            )
            return [self._make_result(
                variant="public_buckets",
                status=Status.SKIPPED,
                evidence=stderr[:500],
                details=skip_detail,
            ), self._make_result(
                variant="bucket_encryption",
                status=Status.SKIPPED,
                evidence=stderr[:500],
                details=skip_detail,
            ), self._make_result(
                variant="bucket_logging",
                status=Status.SKIPPED,
                evidence=stderr[:500],
                details=skip_detail,
            )]

        try:
            bucket_data = json.loads(stdout)
        except json.JSONDecodeError:
            return [self._make_result(
                variant="public_buckets",
                status=Status.ERROR,
                evidence=stdout[:300],
                details="Failed to parse aws s3api list-buckets JSON output.",
            )]

        all_buckets = [b["Name"] for b in bucket_data.get("Buckets", [])]

        throttle = self._get_throttle("cloud.s3_buckets")
        max_buckets = throttle.get("max_buckets", 20)
        buckets = all_buckets[:max_buckets]

        # --- Variant 1: public_buckets ---
        public_buckets = []
        checked_public = 0
        for bucket in buckets:
            rc2, out2, _ = await self._run_aws(
                "s3api", "get-public-access-block", "--bucket", bucket, "--output", "json"
            )
            if rc2 != 0:
                # NoSuchPublicAccessBlockConfiguration means no block at all = vulnerable
                public_buckets.append((bucket, "no public-access-block configuration found"))
                checked_public += 1
                continue
            try:
                pab = json.loads(out2).get("PublicAccessBlockConfiguration", {})
            except json.JSONDecodeError:
                checked_public += 1
                continue
            weak = []
            if not pab.get("BlockPublicAcls", False):
                weak.append("BlockPublicAcls=false")
            if not pab.get("BlockPublicPolicy", False):
                weak.append("BlockPublicPolicy=false")
            if not pab.get("IgnorePublicAcls", False):
                weak.append("IgnorePublicAcls=false")
            if not pab.get("RestrictPublicBuckets", False):
                weak.append("RestrictPublicBuckets=false")
            if weak:
                public_buckets.append((bucket, ", ".join(weak)))
            checked_public += 1

        if public_buckets:
            evidence_lines = [f"{b}: {reason}" for b, reason in public_buckets]
            results.append(self._make_result(
                variant="public_buckets",
                status=Status.VULNERABLE,
                severity=Severity.CRITICAL,
                evidence="\n".join(evidence_lines[:20]),
                details=(
                    f"{len(public_buckets)} of {checked_public} buckets have weak public-access-block settings. "
                    f"Buckets: {', '.join(b for b, _ in public_buckets[:10])}"
                ),
                request={"command": "aws s3api get-public-access-block", "buckets_checked": checked_public},
                response={"vulnerable_buckets": len(public_buckets), "total_buckets": len(all_buckets)},
            ))
        else:
            results.append(self._make_result(
                variant="public_buckets",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"All {checked_public} checked buckets have public access blocked.",
                details=f"Checked {checked_public} of {len(all_buckets)} total buckets.",
                request={"command": "aws s3api get-public-access-block", "buckets_checked": checked_public},
                response={"vulnerable_buckets": 0, "total_buckets": len(all_buckets)},
            ))

        # --- Variant 2: bucket_encryption ---
        unencrypted = []
        checked_enc = 0
        for bucket in buckets:
            rc2, out2, err2 = await self._run_aws(
                "s3api", "get-bucket-encryption", "--bucket", bucket, "--output", "json"
            )
            if rc2 != 0:
                if "ServerSideEncryptionConfigurationNotFoundError" in err2 or "NoSuchBucket" not in err2:
                    unencrypted.append(bucket)
            checked_enc += 1

        if unencrypted:
            results.append(self._make_result(
                variant="bucket_encryption",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence="\n".join(unencrypted[:20]),
                details=(
                    f"{len(unencrypted)} of {checked_enc} buckets lack default server-side encryption. "
                    "Data at rest may be unencrypted. Enable SSE-S3 or SSE-KMS on each bucket."
                ),
                request={"command": "aws s3api get-bucket-encryption", "buckets_checked": checked_enc},
                response={"unencrypted_buckets": len(unencrypted), "total_checked": checked_enc},
            ))
        else:
            results.append(self._make_result(
                variant="bucket_encryption",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"All {checked_enc} checked buckets have default encryption configured.",
                details=f"Checked {checked_enc} of {len(all_buckets)} total buckets.",
                request={"command": "aws s3api get-bucket-encryption", "buckets_checked": checked_enc},
                response={"unencrypted_buckets": 0, "total_checked": checked_enc},
            ))

        # --- Variant 3: bucket_logging ---
        no_logging = []
        checked_log = 0
        for bucket in buckets:
            rc2, out2, _ = await self._run_aws(
                "s3api", "get-bucket-logging", "--bucket", bucket, "--output", "json"
            )
            if rc2 == 0:
                try:
                    log_data = json.loads(out2)
                    if not log_data.get("LoggingEnabled"):
                        no_logging.append(bucket)
                except json.JSONDecodeError:
                    no_logging.append(bucket)
            checked_log += 1

        if no_logging:
            results.append(self._make_result(
                variant="bucket_logging",
                status=Status.PARTIAL,
                severity=Severity.MEDIUM,
                evidence="\n".join(no_logging[:20]),
                details=(
                    f"{len(no_logging)} of {checked_log} buckets have no access logging enabled. "
                    "Without logging, unauthorized access may go undetected."
                ),
                request={"command": "aws s3api get-bucket-logging", "buckets_checked": checked_log},
                response={"no_logging_buckets": len(no_logging), "total_checked": checked_log},
            ))
        else:
            results.append(self._make_result(
                variant="bucket_logging",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"All {checked_log} checked buckets have access logging enabled.",
                details=f"Checked {checked_log} of {len(all_buckets)} total buckets.",
                request={"command": "aws s3api get-bucket-logging", "buckets_checked": checked_log},
                response={"no_logging_buckets": 0, "total_checked": checked_log},
            ))

        return results
