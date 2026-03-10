# Willie (MailCow) Security Mitigation Plan

**Date Created:** 2026-03-09
**Target System:** willie (email.northwoodsmail.com)
**Scan Reference:** willie-cve-scan-2026-03-09.md
**Current Security Rating:** 8/10 (GOOD)
**Target Security Rating:** 9.5/10 (EXCELLENT)

---

## Executive Summary

This mitigation plan addresses findings from the comprehensive AWS-compliant security scan performed on willie (MailCow server). While the system has a strong security foundation (automated updates, backups, modern infrastructure), several critical and high-priority items require immediate attention to achieve enterprise-grade security posture.

**Timeline:** 90 days to full remediation
**Estimated Effort:** 16-24 hours total
**Cost Impact:** Minimal (tools are free/open-source)

---

## Mitigation Items by Priority

### 🔴 CRITICAL Priority (0-7 Days)

#### MIT-WILLIE-001: Pin ofelia Container Version

**Current State:**
- ofelia container using `:latest` tag
- Risk: Unpredictable updates, potential breaking changes
- CVSS Score: 7.5 (HIGH)

**Target State:**
- Pin to specific stable version (e.g., v0.3.8)

**Remediation Steps:**

1. **Backup current configuration**
   ```bash
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net
   cd /opt/mailcow-dockerized
   cp docker-compose.yml docker-compose.yml.backup-$(date +%Y%m%d)
   ```

2. **Identify latest stable ofelia version**
   ```bash
   # Check Docker Hub for latest stable tag
   curl -s https://hub.docker.com/v2/repositories/mcuadros/ofelia/tags/ | jq -r '.results[].name' | grep -v latest | head -5
   ```

3. **Update docker-compose.yml**
   ```bash
   # Find ofelia service in docker-compose.yml
   grep -A 5 "mcuadros/ofelia" docker-compose.yml

   # Change:
   #   image: mcuadros/ofelia:latest
   # To:
   #   image: mcuadros/ofelia:v0.3.8
   ```

4. **Apply changes**
   ```bash
   docker compose pull
   docker compose up -d
   docker compose ps | grep ofelia
   ```

5. **Verify functionality**
   ```bash
   docker logs mailcowdockerized-ofelia-mailcow-1 --tail 50
   # Check that scheduled jobs are still running
   ```

**Validation:**
- [ ] docker-compose.yml uses versioned tag
- [ ] Container recreated successfully
- [ ] Logs show normal operation
- [ ] Scheduled jobs executing correctly

**Rollback Plan:**
```bash
cd /opt/mailcow-dockerized
cp docker-compose.yml.backup-YYYYMMDD docker-compose.yml
docker compose up -d
```

**Owner:** Systems Administrator
**Target Date:** 2026-03-16 (7 days)
**Status:** 🔴 OPEN

---

#### MIT-WILLIE-002: Install and Run Trivy Container CVE Scanner

**Current State:**
- 15 MailCow container images not scanned for CVEs
- Unknown vulnerability exposure in container stack
- No automated container scanning

**Target State:**
- Trivy installed and operational
- All containers scanned for CVEs
- Critical/High CVEs documented and remediated

**Remediation Steps:**

1. **Install Trivy on willie**
   ```bash
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net

   # Add Trivy repository
   sudo apt-get install wget apt-transport-https gnupg lsb-release
   wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
   echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list

   sudo apt-get update
   sudo apt-get install trivy
   ```

2. **Initial CVE database download**
   ```bash
   trivy image --download-db-only
   ```

3. **Scan all MailCow containers**
   ```bash
   # Create scan results directory
   mkdir -p /home/ubuntu/trivy-scans

   # Scan each container image
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/nginx:1.03 | tee /home/ubuntu/trivy-scans/nginx-1.03.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/dovecot:2.34 | tee /home/ubuntu/trivy-scans/dovecot-2.34.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/postfix:1.80 | tee /home/ubuntu/trivy-scans/postfix-1.80.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/rspamd:2.2 | tee /home/ubuntu/trivy-scans/rspamd-2.2.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/phpfpm:1.93 | tee /home/ubuntu/trivy-scans/phpfpm-1.93.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/clamd:1.70 | tee /home/ubuntu/trivy-scans/clamd-1.70.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/sogo:1.133 | tee /home/ubuntu/trivy-scans/sogo-1.133.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/watchdog:2.08 | tee /home/ubuntu/trivy-scans/watchdog-2.08.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/acme:1.93 | tee /home/ubuntu/trivy-scans/acme-1.93.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/netfilter:1.61 | tee /home/ubuntu/trivy-scans/netfilter-1.61.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/dockerapi:2.11 | tee /home/ubuntu/trivy-scans/dockerapi-2.11.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/olefy:1.15 | tee /home/ubuntu/trivy-scans/olefy-1.15.txt
   trivy image --severity HIGH,CRITICAL --format table ghcr.io/mailcow/unbound:1.24 | tee /home/ubuntu/trivy-scans/unbound-1.24.txt
   trivy image --severity HIGH,CRITICAL --format table redis:7.4.2-alpine | tee /home/ubuntu/trivy-scans/redis-7.4.2.txt
   trivy image --severity HIGH,CRITICAL --format table mariadb:10.11 | tee /home/ubuntu/trivy-scans/mariadb-10.11.txt
   trivy image --severity HIGH,CRITICAL --format table memcached:alpine | tee /home/ubuntu/trivy-scans/memcached-alpine.txt
   ```

4. **Generate consolidated report**
   ```bash
   cat /home/ubuntu/trivy-scans/*.txt > /home/ubuntu/trivy-consolidated-report.txt
   grep -E "CRITICAL|HIGH" /home/ubuntu/trivy-consolidated-report.txt > /home/ubuntu/trivy-findings.txt
   ```

5. **Copy results to alfred for analysis**
   ```bash
   # On alfred
   rsync -avz -e "ssh -i ~/.ssh/bq_laptop_rsa" ubuntu@mailcow.tailce791f.ts.net:/home/ubuntu/trivy-scans/ /opt/claude-workspace/projects/cyber-guardian/findings/willie/trivy-scans/
   ```

6. **Triage CVE findings**
   - Review each CRITICAL/HIGH CVE
   - Determine if MailCow updates are available
   - Document remediation plan for each CVE

**Validation:**
- [ ] Trivy installed successfully
- [ ] All 16 container images scanned
- [ ] CVE findings documented
- [ ] Critical/High CVEs have remediation plan

**Expected Findings:**
- Likely 10-50 CVEs across all containers
- Most will be in base OS layers (Alpine, Ubuntu)
- MailCow may have updates available for some images

**Automated Scanning (Follow-up):**
Create weekly scan cron job:
```bash
# /etc/cron.weekly/trivy-scan-mailcow
#!/bin/bash
trivy image --download-db-only
for image in $(docker ps --format '{{.Image}}'); do
    trivy image --severity CRITICAL,HIGH --format json $image > /var/log/trivy-$(echo $image | tr '/:' '_')-$(date +%Y%m%d).json
done
```

**Owner:** Security Team
**Target Date:** 2026-03-16 (7 days)
**Status:** 🔴 OPEN

---

### 🟠 HIGH Priority (8-30 Days)

#### MIT-WILLIE-003: Verify EC2 IMDSv2 Enforcement

**Current State:**
- Unknown if IMDSv2 is enforced
- IMDSv1 is deprecated due to SSRF vulnerability (CVE-2019-5021)

**Target State:**
- EC2 instance requires IMDSv2 (IMDSv1 disabled)

**Remediation Steps:**

1. **Check current IMDS configuration**
   ```bash
   # On local machine with AWS CLI
   aws ec2 describe-instances \
     --filters "Name=tag:Name,Values=willie" \
     --query 'Reservations[].Instances[].{InstanceId:InstanceId,IMDSv2:MetadataOptions.HttpTokens}' \
     --output table
   ```

2. **Enforce IMDSv2 if not already enabled**
   ```bash
   INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=willie" --query 'Reservations[].Instances[].InstanceId' --output text)

   aws ec2 modify-instance-metadata-options \
     --instance-id $INSTANCE_ID \
     --http-tokens required \
     --http-put-response-hop-limit 1
   ```

3. **Verify on willie instance**
   ```bash
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net

   # Test IMDSv1 (should fail)
   curl -s http://169.254.169.254/latest/meta-data/instance-id
   # Expected: 401 Unauthorized

   # Test IMDSv2 (should succeed)
   TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
   curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id
   # Expected: i-xxxxxxxxx (instance ID)
   ```

**Validation:**
- [ ] IMDSv2 required in AWS console
- [ ] IMDSv1 requests return 401
- [ ] IMDSv2 requests succeed
- [ ] No application disruption

**Risk Assessment:**
- **Risk:** MailCow containers may use IMDS internally
- **Mitigation:** Test thoroughly before enforcing
- **Rollback:** Change HttpTokens back to "optional"

**Owner:** Cloud Infrastructure Team
**Target Date:** 2026-03-23 (14 days)
**Status:** 🟠 OPEN

---

#### MIT-WILLIE-004: Verify EBS Volume Encryption

**Current State:**
- Unknown if root EBS volume is encrypted at rest
- AWS best practice: encrypt all EBS volumes

**Target State:**
- Root volume encrypted with AWS KMS

**Remediation Steps:**

1. **Check current encryption status**
   ```bash
   # Find volume ID for willie instance
   INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=willie" --query 'Reservations[].Instances[].InstanceId' --output text)

   VOLUME_ID=$(aws ec2 describe-instances --instance-id $INSTANCE_ID --query 'Reservations[].Instances[].BlockDeviceMappings[0].Ebs.VolumeId' --output text)

   # Check encryption
   aws ec2 describe-volumes --volume-id $VOLUME_ID --query 'Volumes[].{VolumeId:VolumeId,Encrypted:Encrypted,Size:Size}' --output table
   ```

2. **If NOT encrypted, create encrypted snapshot and migrate**

   **WARNING:** This requires downtime. Schedule maintenance window.

   ```bash
   # Create snapshot of current volume
   SNAPSHOT_ID=$(aws ec2 create-snapshot \
     --volume-id $VOLUME_ID \
     --description "Willie pre-encryption backup $(date +%Y-%m-%d)" \
     --query 'SnapshotId' \
     --output text)

   # Wait for snapshot to complete
   aws ec2 wait snapshot-completed --snapshot-ids $SNAPSHOT_ID

   # Create encrypted copy
   ENCRYPTED_SNAPSHOT=$(aws ec2 copy-snapshot \
     --source-snapshot-id $SNAPSHOT_ID \
     --source-region us-east-1 \
     --description "Willie encrypted snapshot" \
     --encrypted \
     --query 'SnapshotId' \
     --output text)

   # Wait for encrypted snapshot
   aws ec2 wait snapshot-completed --snapshot-ids $ENCRYPTED_SNAPSHOT

   # Create encrypted volume from snapshot
   ENCRYPTED_VOLUME=$(aws ec2 create-volume \
     --snapshot-id $ENCRYPTED_SNAPSHOT \
     --availability-zone us-east-1a \
     --encrypted \
     --query 'VolumeId' \
     --output text)

   # DOWNTIME BEGINS
   # Stop instance
   aws ec2 stop-instances --instance-ids $INSTANCE_ID
   aws ec2 wait instance-stopped --instance-ids $INSTANCE_ID

   # Detach old volume
   aws ec2 detach-volume --volume-id $VOLUME_ID
   aws ec2 wait volume-available --volume-ids $VOLUME_ID

   # Attach encrypted volume
   aws ec2 attach-volume \
     --volume-id $ENCRYPTED_VOLUME \
     --instance-id $INSTANCE_ID \
     --device /dev/sda1

   # Start instance
   aws ec2 start-instances --instance-ids $INSTANCE_ID
   aws ec2 wait instance-running --instance-ids $INSTANCE_ID
   # DOWNTIME ENDS (~10-15 minutes)
   ```

3. **Verify encryption and functionality**
   ```bash
   # Check new volume encryption
   aws ec2 describe-volumes --volume-id $ENCRYPTED_VOLUME --query 'Volumes[].Encrypted'

   # SSH to instance
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net "docker ps"

   # Verify MailCow services
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net "cd /opt/mailcow-dockerized && docker compose ps"
   ```

**Validation:**
- [ ] EBS volume encrypted confirmed
- [ ] Instance boots successfully
- [ ] All MailCow containers running
- [ ] Email send/receive functional
- [ ] Old unencrypted volume backed up

**Rollback Plan:**
- Keep old unencrypted volume for 30 days
- Can reattach if issues arise
- AWS Backup still has snapshots

**Owner:** Cloud Infrastructure Team
**Target Date:** 2026-03-30 (21 days)
**Status:** 🟠 OPEN
**Maintenance Window Required:** Yes (10-15 minutes downtime)

---

#### MIT-WILLIE-005: Review and Harden Security Groups

**Current State:**
- Security group rules need review
- SSH may be open to 0.0.0.0/0
- Need to restrict to Tailscale IPs only

**Target State:**
- SSH restricted to known IPs
- Only required email ports publicly accessible
- All other ports blocked

**Required Open Ports (Public):**
- TCP 25 (SMTP)
- TCP 587 (SMTP submission)
- TCP 465 (SMTPS)
- TCP 993 (IMAPS)
- TCP 995 (POP3S)
- TCP 443 (HTTPS - webmail)
- TCP 80 (HTTP - Let's Encrypt challenges only)

**Required Open Ports (Restricted):**
- TCP 22 (SSH - Tailscale IPs only)

**Remediation Steps:**

1. **Audit current security group**
   ```bash
   INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=willie" --query 'Reservations[].Instances[].InstanceId' --output text)

   SG_ID=$(aws ec2 describe-instances --instance-id $INSTANCE_ID --query 'Reservations[].Instances[].SecurityGroups[0].GroupId' --output text)

   aws ec2 describe-security-groups --group-ids $SG_ID --output table
   ```

2. **Document current rules**
   ```bash
   aws ec2 describe-security-groups --group-ids $SG_ID --query 'SecurityGroups[].IpPermissions[]' --output json > /tmp/willie-sg-current.json
   ```

3. **Create new restrictive rules**
   ```bash
   # Remove overly permissive SSH rule (if exists)
   aws ec2 revoke-security-group-ingress \
     --group-id $SG_ID \
     --protocol tcp \
     --port 22 \
     --cidr 0.0.0.0/0

   # Add Tailscale CGNAT range for SSH
   aws ec2 authorize-security-group-ingress \
     --group-id $SG_ID \
     --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=100.64.0.0/10,Description="Tailscale CGNAT"}]'

   # Verify email ports are open to all
   aws ec2 authorize-security-group-ingress \
     --group-id $SG_ID \
     --ip-permissions \
       IpProtocol=tcp,FromPort=25,ToPort=25,IpRanges='[{CidrIp=0.0.0.0/0,Description="SMTP"}]' \
       IpProtocol=tcp,FromPort=587,ToPort=587,IpRanges='[{CidrIp=0.0.0.0/0,Description="SMTP Submission"}]' \
       IpProtocol=tcp,FromPort=465,ToPort=465,IpRanges='[{CidrIp=0.0.0.0/0,Description="SMTPS"}]' \
       IpProtocol=tcp,FromPort=993,ToPort=993,IpRanges='[{CidrIp=0.0.0.0/0,Description="IMAPS"}]' \
       IpProtocol=tcp,FromPort=995,ToPort=995,IpRanges='[{CidrIp=0.0.0.0/0,Description="POP3S"}]' \
       IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=0.0.0.0/0,Description="HTTPS"}]' \
       IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges='[{CidrIp=0.0.0.0/0,Description="HTTP - ACME"}]'
   ```

4. **Verify SSH access via Tailscale**
   ```bash
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net "echo 'SSH access confirmed'"
   ```

**Validation:**
- [ ] SSH only accessible via Tailscale
- [ ] Email ports publicly accessible
- [ ] No unnecessary ports open
- [ ] Security group rules documented

**Owner:** Cloud Infrastructure Team
**Target Date:** 2026-03-30 (21 days)
**Status:** 🟠 OPEN

---

### 🟡 MEDIUM Priority (31-60 Days)

#### MIT-WILLIE-006: Run CIS Benchmark Audit with Lynis

**Current State:**
- No formal CIS benchmark compliance assessment
- Unknown security hardening gaps

**Target State:**
- Lynis installed and executed
- CIS benchmark gaps documented
- Remediation plan for findings

**Remediation Steps:**

1. **Install Lynis**
   ```bash
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net
   sudo apt-get update
   sudo apt-get install lynis
   ```

2. **Run initial audit**
   ```bash
   sudo lynis audit system --quick
   ```

3. **Generate full report**
   ```bash
   sudo lynis audit system --report-file /var/log/lynis-report.txt
   cat /var/log/lynis-report.txt | grep -A 5 "Hardening index"
   ```

4. **Copy report to alfred**
   ```bash
   # On alfred
   scp -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net:/var/log/lynis-report.txt /opt/claude-workspace/projects/cyber-guardian/findings/willie/
   ```

5. **Review and prioritize findings**
   - Parse Lynis suggestions
   - Categorize by impact
   - Create sub-tasks for high-impact items

**Validation:**
- [ ] Lynis installed
- [ ] Full system audit completed
- [ ] Hardening index calculated
- [ ] Top 10 findings documented

**Expected Outcome:**
- Hardening index: 60-75 (typical for production server)
- Target after remediation: 85+

**Owner:** Security Team
**Target Date:** 2026-04-15 (37 days)
**Status:** 🟡 OPEN

---

#### MIT-WILLIE-007: Implement File Integrity Monitoring

**Current State:**
- No file integrity monitoring
- Cannot detect unauthorized file changes

**Target State:**
- AIDE installed and configured
- Critical paths monitored
- Daily integrity checks

**Paths to Monitor:**
- /etc/
- /opt/mailcow-dockerized/
- /root/.ssh/
- /home/ubuntu/.ssh/
- /usr/local/bin/

**Remediation Steps:**

1. **Install AIDE**
   ```bash
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net
   sudo apt-get install aide aide-common
   ```

2. **Configure AIDE rules**
   ```bash
   sudo nano /etc/aide/aide.conf
   # Add custom rules for MailCow paths
   /opt/mailcow-dockerized/ R+sha512
   ```

3. **Initialize database**
   ```bash
   sudo aideinit
   sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
   ```

4. **Set up daily checks**
   ```bash
   sudo nano /etc/cron.daily/aide-check
   # Add:
   #!/bin/bash
   /usr/bin/aide --check | mail -s "AIDE Report - Willie" admin@quigs.com

   sudo chmod +x /etc/cron.daily/aide-check
   ```

**Validation:**
- [ ] AIDE installed
- [ ] Database initialized
- [ ] Daily checks configured
- [ ] Test alert received

**Owner:** Security Team
**Target Date:** 2026-04-30 (52 days)
**Status:** 🟡 OPEN

---

#### MIT-WILLIE-008: Review MailCow Configuration Hardening

**Current State:**
- Default MailCow configuration
- Need to verify security settings

**Target State:**
- Security-hardened MailCow configuration
- TLS 1.2+ only
- Strong cipher suites
- Security headers enabled

**Remediation Steps:**

1. **Audit mailcow.conf**
   ```bash
   ssh -i ~/.ssh/bq_laptop_rsa ubuntu@mailcow.tailce791f.ts.net
   cat /opt/mailcow-dockerized/mailcow.conf | grep -E "SKIP_|API_|ADMIN_"
   ```

2. **Verify security-critical settings**
   - SKIP_LETS_ENCRYPT=n (Let's Encrypt enabled)
   - SKIP_CLAMD=n (ClamAV enabled)
   - Strong DBPASS (database password)
   - API_ALLOW_FROM (restrict API access)

3. **Review nginx TLS configuration**
   ```bash
   docker exec mailcowdockerized-nginx-mailcow-1 cat /etc/nginx/nginx.conf | grep -A 10 ssl_protocols
   ```

4. **Ensure TLS 1.2+ only**
   - Disable TLS 1.0 and 1.1
   - Use modern cipher suites
   - HSTS enabled

**Validation:**
- [ ] mailcow.conf security settings verified
- [ ] TLS 1.2+ only
- [ ] Strong ciphers configured
- [ ] Security headers present

**Owner:** MailCow Administrator
**Target Date:** 2026-04-30 (52 days)
**Status:** 🟡 OPEN

---

### 🟢 LOW Priority (61-90 Days)

#### MIT-WILLIE-009: Automate Container Vulnerability Scanning

**Current State:**
- Manual Trivy scans only
- No automated CVE monitoring

**Target State:**
- Weekly automated Trivy scans
- Email alerts on new CVEs
- CVE tracking dashboard

**Remediation Steps:**

1. **Create scan script**
   ```bash
   sudo nano /opt/scripts/weekly-trivy-scan.sh
   ```

2. **Configure email alerts**
   ```bash
   # Install mailutils
   sudo apt-get install mailutils

   # Test email
   echo "Test" | mail -s "Test from Willie" admin@quigs.com
   ```

3. **Set up cron job**
   ```bash
   sudo crontab -e
   # Add:
   0 4 * * 0 /opt/scripts/weekly-trivy-scan.sh
   ```

**Validation:**
- [ ] Script created and tested
- [ ] Email alerts working
- [ ] First weekly scan completed

**Owner:** DevOps Team
**Target Date:** 2026-05-15 (67 days)
**Status:** 🟢 OPEN

---

#### MIT-WILLIE-010: Document Security Configuration in SERVERS.md

**Current State:**
- SERVERS.md has basic info
- Security configuration not documented

**Target State:**
- Complete security documentation
- Firewall rules documented
- Compliance status documented

**Remediation Steps:**

1. **Update SERVERS.md willie section**
   - Add Security section
   - Document firewall rules
   - Document TLS configuration
   - Document backup configuration
   - Document compliance status

2. **Add security monitoring section**
   - Trivy scan schedule
   - Lynis audit schedule
   - AIDE check schedule

**Validation:**
- [ ] SERVERS.md updated
- [ ] All security config documented
- [ ] Reviewed by security team

**Owner:** Documentation Team
**Target Date:** 2026-05-30 (82 days)
**Status:** 🟢 OPEN

---

#### MIT-WILLIE-011: Review IAM Permissions

**Current State:**
- Unknown IAM role permissions
- Need to verify least privilege

**Target State:**
- IAM role permissions documented
- Least privilege enforced
- Unnecessary permissions removed

**Remediation Steps:**

1. **Identify IAM role**
   ```bash
   INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=willie" --query 'Reservations[].Instances[].InstanceId' --output text)

   IAM_ROLE=$(aws ec2 describe-instances --instance-id $INSTANCE_ID --query 'Reservations[].Instances[].IamInstanceProfile.Arn' --output text)
   ```

2. **Review attached policies**
   ```bash
   aws iam list-attached-role-policies --role-name <role-name>
   aws iam list-role-policies --role-name <role-name>
   ```

3. **Document required permissions**
   - AWS Backup access
   - CloudWatch Logs (if used)
   - Systems Manager (if used)

4. **Remove unnecessary permissions**

**Validation:**
- [ ] IAM role documented
- [ ] Permissions reviewed
- [ ] Least privilege enforced
- [ ] AWS Backup still functional

**Owner:** Cloud Security Team
**Target Date:** 2026-06-07 (90 days)
**Status:** 🟢 OPEN

---

## Implementation Timeline

### Week 1-2 (🔴 Critical)
- Day 1-3: MIT-WILLIE-001 (Pin ofelia version)
- Day 4-7: MIT-WILLIE-002 (Trivy scan all containers)

### Week 3-4 (🟠 High)
- Day 14: MIT-WILLIE-003 (IMDSv2 enforcement)
- Day 21: MIT-WILLIE-004 (EBS encryption) - **Maintenance window required**
- Day 21: MIT-WILLIE-005 (Security group hardening)

### Week 5-8 (🟡 Medium)
- Day 37: MIT-WILLIE-006 (Lynis CIS audit)
- Day 52: MIT-WILLIE-007 (AIDE file integrity)
- Day 52: MIT-WILLIE-008 (MailCow hardening review)

### Week 9-13 (🟢 Low)
- Day 67: MIT-WILLIE-009 (Automated scanning)
- Day 82: MIT-WILLIE-010 (Documentation update)
- Day 90: MIT-WILLIE-011 (IAM review)

---

## Success Metrics

**Target Security Rating:** 9.5/10

**Key Performance Indicators:**

1. **Vulnerability Management**
   - Zero critical CVEs in containers (target: 100% remediation)
   - <5 high CVEs in containers (target: <5)
   - All CVEs documented and tracked

2. **AWS Compliance**
   - IMDSv2 enforced: ✅
   - EBS encryption: ✅
   - Security groups hardened: ✅
   - IAM least privilege: ✅

3. **System Hardening**
   - Lynis hardening index: >85
   - AIDE file integrity: Active
   - Automated scanning: Weekly

4. **Operational Excellence**
   - Security documentation: Complete
   - Incident response plan: Documented
   - Quarterly security audits: Scheduled

---

## Risk Assessment

### High-Risk Items Requiring Careful Execution

1. **EBS Encryption Migration**
   - **Risk:** Data loss, downtime >15 minutes
   - **Mitigation:** Full backup before migration, test in dev first
   - **Rollback:** Keep old volume for 30 days

2. **Security Group Changes**
   - **Risk:** Lock out SSH access
   - **Mitigation:** Test Tailscale connectivity first, have console access ready
   - **Rollback:** Re-add 0.0.0.0/0 SSH rule via AWS console

3. **ofelia Container Update**
   - **Risk:** Cron jobs stop running
   - **Mitigation:** Verify logs after update, keep backup docker-compose.yml
   - **Rollback:** Revert to :latest tag

---

## Budget and Resources

### Software Costs
- Trivy: Free (open source)
- Lynis: Free (open source)
- AIDE: Free (open source)
- **Total:** $0

### AWS Costs
- EBS snapshot storage: ~$0.05/GB/month × 50GB = $2.50/month
- KMS encryption: Included in AWS Free Tier for first 20,000 requests/month
- **Total:** ~$2.50/month (one-time snapshot cost)

### Labor Estimate
- Critical items (MIT-001, 002): 8 hours
- High priority (MIT-003, 004, 005): 8 hours
- Medium priority (MIT-006, 007, 008): 6 hours
- Low priority (MIT-009, 010, 011): 4 hours
- **Total:** 26 hours over 90 days

---

## Maintenance and Ongoing Operations

### Weekly Tasks
- Review Trivy scan results
- Check AIDE integrity reports
- Review auth.log for suspicious activity

### Monthly Tasks
- Review AWS Backup success/failure
- Update container images if CVEs found
- Review CloudWatch metrics (if enabled)

### Quarterly Tasks
- Run full Lynis audit
- Review and update this mitigation plan
- Conduct tabletop security incident exercise
- Review IAM permissions

---

## Appendix A: Emergency Contacts

**Systems Team:**
- Primary: admin@quigs.com
- Secondary: Tailscale admin console

**AWS Support:**
- Support Plan: (Document current support tier)
- Support URL: https://console.aws.amazon.com/support

**MailCow Support:**
- Documentation: https://docs.mailcow.email/
- Community Forum: https://community.mailcow.email/

---

## Appendix B: Rollback Procedures

### General Rollback Principles
1. Keep all backups for 30 days minimum
2. Document configuration before changes
3. Test rollback in dev/staging first
4. Have AWS console access ready

### Critical Rollback Commands

**Revert ofelia to latest:**
```bash
cd /opt/mailcow-dockerized
git checkout docker-compose.yml
docker compose up -d
```

**Revert security group:**
```bash
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0
```

**Reattach old EBS volume:**
```bash
aws ec2 stop-instances --instance-ids $INSTANCE_ID
aws ec2 detach-volume --volume-id $NEW_VOLUME_ID
aws ec2 attach-volume --volume-id $OLD_VOLUME_ID --instance-id $INSTANCE_ID --device /dev/sda1
aws ec2 start-instances --instance-ids $INSTANCE_ID
```

---

## Approval and Sign-off

**Plan Author:** Cyber-Guardian Automated Security Assessment
**Date Created:** 2026-03-09
**Review Required By:** Systems Administrator, Security Team
**Approval Required From:** Infrastructure Manager

**Approvals:**
- [ ] Systems Administrator
- [ ] Security Team Lead
- [ ] Infrastructure Manager
- [ ] Budget Approval (minimal cost)

**Implementation Start Date:** _____________
**Target Completion Date:** 2026-06-07 (90 days)

---

**END OF MITIGATION PLAN**
