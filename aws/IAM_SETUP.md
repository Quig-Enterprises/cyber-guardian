# AWS IAM Configuration for Compliance Scanner

**User:** `groundtruth-studio-dev-server`
**AWS Account:** 051951709252
**Region:** us-east-2 (Ohio)

---

## Overview

The Cyber-Guardian compliance scanner needs read-only AWS permissions to perform security audits on EC2 instances and EBS volumes.

**Current Status:** User lacks required permissions
**Required Permissions:** EC2 read-only access

---

## Required Permissions

The compliance scanner needs the following EC2 permissions to audit:

### EC2 Instance Checks
- **IMDSv2 enforcement** - Requires `ec2:DescribeInstances` and `ec2:DescribeInstanceAttribute`
- **Security group audits** - Requires `ec2:DescribeSecurityGroups`
- **Network configuration** - Requires `ec2:DescribeNetworkInterfaces`

### EBS Volume Checks
- **Volume encryption** - Requires `ec2:DescribeVolumes` and `ec2:DescribeVolumeAttribute`
- **Snapshot encryption** - Requires `ec2:DescribeSnapshots`

### General
- **Instance metadata** - Requires `ec2:DescribeTags`
- **AMI information** - Requires `ec2:DescribeImages`

---

## Implementation Options

### Option 1: Create Inline Policy (Recommended)

**Steps via AWS Console:**

1. Navigate to IAM → Users → `groundtruth-studio-dev-server`
2. Click "Add permissions" → "Create inline policy"
3. Switch to JSON tab
4. Paste the contents of `compliance-scanner-iam-policy.json`
5. Name: `CyberGuardianComplianceScanner`
6. Click "Create policy"

**Verify:**
```bash
aws iam list-user-policies --user-name groundtruth-studio-dev-server
# Should show: CyberGuardianComplianceScanner
```

### Option 2: Attach Managed Policy

**Using AWS CLI (requires IAM admin privileges):**

```bash
# Create the policy
aws iam create-policy \
  --policy-name CyberGuardianComplianceScanner \
  --policy-document file:///opt/claude-workspace/projects/cyber-guardian/aws/compliance-scanner-iam-policy.json \
  --description "Read-only EC2 access for Cyber-Guardian compliance scanner"

# Attach to user
aws iam attach-user-policy \
  --user-name groundtruth-studio-dev-server \
  --policy-arn arn:aws:iam::051951709252:policy/CyberGuardianComplianceScanner
```

### Option 3: Use AWS Managed Policy (Broadest Access)

**Attach AWS ReadOnlyAccess policy:**

```bash
aws iam attach-user-policy \
  --user-name groundtruth-studio-dev-server \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

**Note:** This grants read access to ALL AWS services. Use only if compliance scanner will expand to other AWS services in the future.

---

## Policy Document

**File:** `/opt/claude-workspace/projects/cyber-guardian/aws/compliance-scanner-iam-policy.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ComplianceScannerEC2ReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeVolumeAttribute",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeImages",
        "ec2:DescribeSnapshots",
        "ec2:DescribeTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ComplianceScannerIMDSv2Check",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstanceAttribute"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Verification Steps

After applying the policy, verify permissions from alfred:

### Test 1: Describe Instances
```bash
aws ec2 describe-instances --region us-east-2 --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key==`Name`].Value|[0]]' --output table
```

**Expected:** Table of EC2 instances
**Error if not working:** `UnauthorizedOperation: You are not authorized to perform: ec2:DescribeInstances`

### Test 2: Describe Volumes
```bash
aws ec2 describe-volumes --region us-east-2 --query 'Volumes[*].[VolumeId,Encrypted,State]' --output table
```

**Expected:** Table of EBS volumes with encryption status
**Error if not working:** `UnauthorizedOperation: You are not authorized to perform: ec2:DescribeVolumes`

### Test 3: Run Compliance Scan
```bash
cd /opt/claude-workspace/projects/cyber-guardian
python3 scripts/compliance-scanner.py --server willie --type aws-ec2 --aws-region us-east-2
```

**Expected:** Successful scan with AWS compliance checks
**Error if not working:** Various `UnauthorizedOperation` errors

---

## Security Considerations

### Read-Only Access
- This policy grants **read-only** access to EC2 resources
- No ability to modify, create, or delete resources
- No access to EC2 instance data (SSH keys, user data with secrets)
- No access to other AWS services (S3, RDS, etc.)

### Scope
- Permissions apply to all regions (`Resource: "*"`)
- This is required because EC2 resource ARNs are region-specific
- Consider adding a region condition if scanning is limited to us-east-2

### Audit Trail
- All API calls are logged in CloudTrail
- Can be monitored for unusual activity
- Policy can be revoked at any time

---

## Current Findings That Will Be Resolved

Once permissions are configured, the compliance scanner will be able to check:

**Willie (AWS EC2 Instance):**
1. ✅ **EBS Volume Encryption** - Currently reported as HIGH severity finding
   - Can verify encryption status
   - Can identify unencrypted volumes

2. ✅ **IMDSv2 Enforcement** - Security best practice
   - Can verify metadata service version
   - Can check if IMDSv1 is disabled

3. ✅ **Security Group Audits** - Firewall rule compliance
   - Can check for overly permissive rules
   - Can verify SSH restrictions

**Peter (AWS EC2 Instance):**
- Same checks as willie
- Currently no findings, but enables ongoing monitoring

---

## Compliance Scanner AWS Integration

### Current Implementation

The compliance scanner has AWS integration built-in:

**File:** `/opt/claude-workspace/projects/cyber-guardian/scripts/compliance-scanner.py`

**AWS Check Classes:**
- `AWSChecks` - Main AWS compliance checks
- `check_ebs_encryption()` - Verifies EBS volume encryption
- `check_imdsv2()` - Verifies IMDSv2 is enforced
- `check_security_groups()` - Audits security group rules

**Usage:**
```bash
python3 compliance-scanner.py \
  --server willie \
  --type aws-ec2 \
  --aws-region us-east-2 \
  --aws-instance-id i-xxxxxxxxx  # Optional - auto-detected if not provided
```

### Auto-Detection

The scanner can auto-detect AWS instance metadata when running on EC2:
- Instance ID from IMDS
- Region from IMDS
- Availability zone from IMDS

When scanning remote AWS instances, provide:
- `--aws-instance-id` - The EC2 instance ID
- `--aws-region` - The AWS region (default: us-east-2)

---

## Database Schema

AWS compliance findings are stored with:

**Table:** `blueteam.compliance_findings`

**AWS-Specific Fields:**
- `aws_resource_id` - EC2 instance ID (e.g., i-0abc123def456)
- `aws_resource_type` - Resource type (e.g., "EC2::Instance", "EC2::Volume")
- `aws_foundational_security` - AWS Foundational Security Best Practices mapping
- `check_category` - Set to "aws"

**Example Query:**
```sql
SELECT
    server_name,
    check_name,
    severity,
    finding_summary,
    aws_resource_id
FROM blueteam.compliance_findings
WHERE check_category = 'aws'
  AND status = 'fail'
ORDER BY severity;
```

---

## Next Steps After IAM Configuration

1. **Verify Permissions** - Run test commands above
2. **Run Initial AWS Scan**:
   ```bash
   cd /opt/claude-workspace/projects/cyber-guardian
   python3 scripts/compliance-scanner.py --server willie --type aws-ec2 --aws-region us-east-2
   ```
3. **Check Database** - Verify findings stored correctly
4. **Resolve Findings** - Address any HIGH severity AWS issues
5. **Schedule Automated Scans** - Add AWS checks to automated scanning

---

## Troubleshooting

### "UnauthorizedOperation" Errors

**Symptom:** `User is not authorized to perform: ec2:DescribeInstances`

**Solutions:**
1. Verify policy is attached to correct user
2. Check policy JSON syntax is valid
3. Wait 1-2 minutes for IAM propagation
4. Verify AWS credentials are configured (`aws configure list`)

### "InvalidInstanceID.NotFound"

**Symptom:** Cannot find instance ID

**Solutions:**
1. Verify instance is in correct region
2. Use `--aws-region` parameter
3. Check instance ID format (starts with `i-`)

### No AWS Findings in Database

**Symptom:** Scan completes but no AWS findings

**Solutions:**
1. Check scan output for errors
2. Verify `--type aws-ec2` parameter used
3. Check database connection
4. Review logs: `/opt/claude-workspace/projects/cyber-guardian/logs/`

---

## References

- **IAM Policy File:** `/opt/claude-workspace/projects/cyber-guardian/aws/compliance-scanner-iam-policy.json`
- **Scanner Script:** `/opt/claude-workspace/projects/cyber-guardian/scripts/compliance-scanner.py`
- **Database Schema:** `/opt/claude-workspace/projects/cyber-guardian/sql/03-compliance-schema.sql`
- **AWS IAM Console:** https://console.aws.amazon.com/iam/home#/users/groundtruth-studio-dev-server

---

**Last Updated:** 2026-03-10
**Status:** Awaiting IAM policy attachment
**IAM User:** groundtruth-studio-dev-server
**AWS Account:** 051951709252
