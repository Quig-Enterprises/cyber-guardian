#!/usr/bin/env bash
set -euo pipefail

# git-push-and-broadcast.sh
# Wrapper around git push that broadcasts commits to Matrix on success.
#
# Usage:
#   ./git-push-and-broadcast.sh [git-push-args...]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Capture what the remote tracking branch points to BEFORE pushing
# This tells us what commits are new to the remote
REMOTE_REF="$(git rev-parse '@{upstream}' 2>/dev/null || echo "")"

# Execute git push with all arguments passed through
if KEYSTONE_BROADCAST_PUSH=1 command git push "$@"; then
    # Push succeeded; broadcast new commits (since the old remote ref)
    if [[ -n "$REMOTE_REF" ]]; then
        "$SCRIPT_DIR/matrix-broadcast-push.sh" --since "$REMOTE_REF"
    else
        "$SCRIPT_DIR/matrix-broadcast-push.sh" --since "HEAD~1"
    fi
else
    exit $?
fi
