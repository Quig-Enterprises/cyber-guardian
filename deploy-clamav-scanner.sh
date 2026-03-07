#!/bin/bash
#
# Deploy ClamAV Upload Scanner to WordPress Sites
#
# Usage:
#   ./deploy-clamav-scanner.sh              # Deploy to all sites
#   ./deploy-clamav-scanner.sh site-name    # Deploy to specific site
#

set -e

PLUGIN_FILE="/var/www/html/wordpress/wp-content/mu-plugins/clamav-upload-scanner.php"
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'

# Check if source plugin exists
if [ ! -f "$PLUGIN_FILE" ]; then
    echo -e "${COLOR_RED}✗ Source plugin not found: $PLUGIN_FILE${COLOR_RESET}"
    exit 1
fi

echo "ClamAV Upload Scanner Deployment"
echo "================================="
echo ""

# Check if ClamAV is running
if ! systemctl is-active --quiet clamav-daemon; then
    echo -e "${COLOR_YELLOW}⚠ ClamAV daemon is not running${COLOR_RESET}"
    echo "Starting ClamAV daemon..."
    sudo systemctl start clamav-daemon
    sleep 2
fi

echo -e "${COLOR_GREEN}✓ ClamAV daemon is running${COLOR_RESET}"
echo ""

# Function to deploy to a site
deploy_to_site() {
    local site_path=$1
    local site_name=$(basename $(dirname $(dirname "$site_path")))

    echo "Deploying to: $site_name"

    # Create mu-plugins directory if it doesn't exist
    if [ ! -d "$site_path" ]; then
        echo "  Creating mu-plugins directory..."
        sudo mkdir -p "$site_path"
    fi

    # Copy plugin
    sudo cp "$PLUGIN_FILE" "$site_path/"

    # Set permissions
    sudo chown www-data:www-data "$site_path/clamav-upload-scanner.php"
    sudo chmod 644 "$site_path/clamav-upload-scanner.php"

    echo -e "  ${COLOR_GREEN}✓ Deployed${COLOR_RESET}"
}

# Deploy based on arguments
if [ $# -eq 0 ]; then
    # Deploy to all sites
    echo "Deploying to all WordPress sites..."
    echo ""

    count=0
    for site_dir in /var/www/html/*/wp-content/mu-plugins; do
        if [ -d "$(dirname $(dirname "$site_dir"))/wp-content" ]; then
            deploy_to_site "$site_dir"
            ((count++))
        fi
    done

    echo ""
    echo -e "${COLOR_GREEN}✓ Deployed to $count sites${COLOR_RESET}"

else
    # Deploy to specific site
    SITE_NAME=$1
    SITE_PATH="/var/www/html/$SITE_NAME/wp-content/mu-plugins"

    if [ ! -d "/var/www/html/$SITE_NAME/wp-content" ]; then
        echo -e "${COLOR_RED}✗ Site not found: $SITE_NAME${COLOR_RESET}"
        exit 1
    fi

    deploy_to_site "$SITE_PATH"
    echo ""
    echo -e "${COLOR_GREEN}✓ Deployment complete${COLOR_RESET}"
fi

# Test deployment
echo ""
echo "Running deployment test..."
TEST_RESULT=$(php /tmp/test-malware-scanner.php | grep -c "✓ PASS")

if [ "$TEST_RESULT" -eq "2" ]; then
    echo -e "${COLOR_GREEN}✓ All tests passed${COLOR_RESET}"
else
    echo -e "${COLOR_YELLOW}⚠ Some tests failed - check manually${COLOR_RESET}"
fi

echo ""
echo "Deployment complete!"
echo ""
echo "To verify, check logs:"
echo "  sudo tail -f /var/log/nginx/error.log | grep 'ClamAV Upload Scanner'"
