#!/bin/bash
#
# Attach Compliance Scanner IAM Policy
#
# This script creates and attaches the necessary IAM policy for the
# Cyber-Guardian compliance scanner to audit AWS resources.
#
# Prerequisites:
# - AWS CLI configured with IAM admin privileges
# - Permissions to create policies and attach them to users
#
# Usage: bash attach-policy.sh

set -e

POLICY_NAME="CyberGuardianComplianceScanner"
USER_NAME="groundtruth-studio-dev-server"
AWS_ACCOUNT="051951709252"
POLICY_FILE="$(dirname "$0")/compliance-scanner-iam-policy.json"

echo "=========================================="
echo "Cyber-Guardian IAM Policy Setup"
echo "=========================================="
echo "Policy Name: $POLICY_NAME"
echo "User: $USER_NAME"
echo "Account: $AWS_ACCOUNT"
echo "=========================================="
echo ""

# Check if policy file exists
if [ ! -f "$POLICY_FILE" ]; then
    echo "ERROR: Policy file not found: $POLICY_FILE"
    exit 1
fi

echo "[1/3] Creating IAM policy..."
POLICY_ARN=$(aws iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document "file://$POLICY_FILE" \
    --description "Read-only EC2 access for Cyber-Guardian compliance scanner" \
    --query 'Policy.Arn' \
    --output text 2>&1)

if [ $? -ne 0 ]; then
    if echo "$POLICY_ARN" | grep -q "EntityAlreadyExists"; then
        echo "Policy already exists. Using existing policy..."
        POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT}:policy/${POLICY_NAME}"
    else
        echo "ERROR: Failed to create policy"
        echo "$POLICY_ARN"
        exit 1
    fi
else
    echo "✓ Policy created: $POLICY_ARN"
fi

echo ""
echo "[2/3] Attaching policy to user..."
aws iam attach-user-policy \
    --user-name "$USER_NAME" \
    --policy-arn "$POLICY_ARN"

if [ $? -eq 0 ]; then
    echo "✓ Policy attached successfully"
else
    echo "ERROR: Failed to attach policy"
    exit 1
fi

echo ""
echo "[3/3] Verifying attachment..."
ATTACHED=$(aws iam list-attached-user-policies \
    --user-name "$USER_NAME" \
    --query "AttachedPolicies[?PolicyName=='$POLICY_NAME'].PolicyName" \
    --output text)

if [ "$ATTACHED" == "$POLICY_NAME" ]; then
    echo "✓ Policy successfully attached and verified"
else
    echo "WARNING: Policy may not be attached correctly"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Wait 1-2 minutes for IAM propagation"
echo "2. Test permissions from alfred server:"
echo "   aws ec2 describe-instances --region us-east-2"
echo "3. Run compliance scan:"
echo "   cd /opt/claude-workspace/projects/cyber-guardian"
echo "   python3 scripts/compliance-scanner.py --server willie --type aws-ec2 --aws-region us-east-2"
echo ""
