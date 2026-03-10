#!/usr/bin/env bash
set -euo pipefail

# matrix-broadcast-push.sh
# Broadcasts git push information to the Matrix #migrations room.
#
# Usage:
#   ./matrix-broadcast-push.sh [--repo-name <name>] [--channel <channel>] [--since <ref>]
#
# Can also be used as a git post-push hook by symlinking:
#   ln -s /opt/project-keystone/scripts/matrix-broadcast-push.sh \
#         /path/to/repo/.git/hooks/post-push

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_CHANNEL="development"
DEFAULT_MIGRATIONS_ROOM="#migrations:artemis-matrix.ecoeyetech.com"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
REPO_NAME=""
CHANNEL=""
SINCE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-name) REPO_NAME="$2"; shift 2 ;;
        --channel)   CHANNEL="$2";   shift 2 ;;
        --since)     SINCE="$2";     shift 2 ;;
        -h|--help)
            cat <<EOF
Usage: $0 [--repo-name <name>] [--channel <channel>] [--since <ref>]

Options:
  --repo-name  Repository display name (default: basename of git root)
  --channel    Broadcast channel: "development" or "production"
               (default: read from matrix-client.conf, or "development")
  --since      Git ref to diff commits from (default: @{push} or previous HEAD)
EOF
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve repo name
# ---------------------------------------------------------------------------
if [[ -z "$REPO_NAME" ]]; then
    REPO_NAME="$(basename "$REPO_ROOT")"
fi

# ---------------------------------------------------------------------------
# Load conf file (matrix-client.conf next to this script)
# ---------------------------------------------------------------------------
# Check scripts/ dir, then repo root, then /etc/keystone/
# Load conf files: repo file first for defaults, /etc/keystone/ second to override
for candidate in "${REPO_ROOT}/matrix-client.conf" "/etc/keystone/matrix-client.conf"; do
    if [[ -f "$candidate" ]]; then
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$key" ]] && continue
            key="${key// /}"
            value="${value#"${value%%[![:space:]]*}"}"  # trim leading whitespace
            if [[ -n "$value" ]]; then
                export "$key=$value"
            fi
        done < "$candidate"
    fi
done

# Resolve channel and migrations room from conf or defaults
if [[ -z "$CHANNEL" ]]; then
    CHANNEL="${MATRIX_CHANNEL:-$DEFAULT_CHANNEL}"
fi
MIGRATIONS_ROOM="${MIGRATIONS_ROOM:-${DEFAULT_MIGRATIONS_ROOM}}"

# ---------------------------------------------------------------------------
# Load credentials from .env (repo root first, then environment)
# ---------------------------------------------------------------------------
ENV_FILE="${REPO_ROOT}/.env"
if [[ -f "$ENV_FILE" ]]; then
    # Export only MATRIX_* vars from .env; avoid clobbering full environment
    while IFS='=' read -r key value; do
        # Skip comments and blank lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        key="${key// /}"
        if [[ "$key" == MATRIX_HOMESERVER || "$key" == MATRIX_BOT_TOKEN ]]; then
            # Strip surrounding quotes if present
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"
            export "$key=$value"
        fi
    done < "$ENV_FILE"
fi

# Validate credentials
[[ -z "${MATRIX_HOMESERVER:-}" ]] && die "MATRIX_HOMESERVER is not set (check .env or environment)"
[[ -z "${MATRIX_BOT_TOKEN:-}" ]]  && die "MATRIX_BOT_TOKEN is not set (check .env or environment)"

# ---------------------------------------------------------------------------
# Resolve --since ref
# ---------------------------------------------------------------------------
if [[ -z "$SINCE" ]]; then
    # Try @{push} (upstream tracking ref at time of push)
    if git rev-parse --verify '@{push}' >/dev/null 2>&1; then
        SINCE="@{push}"
    else
        # Fall back to previous HEAD (ORIG_HEAD set by git during push)
        if git rev-parse --verify 'ORIG_HEAD' >/dev/null 2>&1; then
            SINCE="ORIG_HEAD"
        else
            # Last resort: one commit back
            SINCE="HEAD~1"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Collect new commits
# ---------------------------------------------------------------------------
log "Collecting commits since ${SINCE}..."

COMMITS_ONELINE=""
if ! COMMITS_ONELINE="$(git log --oneline "${SINCE}..HEAD" 2>/dev/null)"; then
    warn "Could not determine commits since ${SINCE}; nothing to broadcast."
    exit 0
fi

if [[ -z "$COMMITS_ONELINE" ]]; then
    log "No new commits since ${SINCE}. Nothing to broadcast."
    exit 0
fi

COMMIT_COUNT="$(echo "$COMMITS_ONELINE" | wc -l | tr -d ' ')"
log "Found ${COMMIT_COUNT} new commit(s)."

# ---------------------------------------------------------------------------
# Detect migration-related changes
# ---------------------------------------------------------------------------
CHANGED_FILES=""
CHANGED_FILES="$(git diff --name-only "${SINCE}..HEAD" 2>/dev/null || true)"

HAS_MIGRATIONS=false
MIGRATION_FILES=""

while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if [[ "$f" =~ ^db/migrations/ ]] || \
       [[ "$f" =~ ^migrations/ ]] || \
       [[ "$f" =~ \.sql$ ]] || \
       [[ "$f" =~ ^docker-compose.*\.yml$ ]] || \
       [[ "$f" == "setup.sh" ]]; then
        HAS_MIGRATIONS=true
        MIGRATION_FILES="${MIGRATION_FILES}${f}"$'\n'
    fi
done <<< "$CHANGED_FILES"

# ---------------------------------------------------------------------------
# Build commit JSON array for Python
# ---------------------------------------------------------------------------
COMMITS_JSON="$(git log --format='{"hash":"%h","subject":"%s","author":"%an","date":"%ci"}' "${SINCE}..HEAD" \
    | python3 -c "
import sys, json
commits = []
for line in sys.stdin:
    line = line.strip()
    if line:
        try:
            commits.append(json.loads(line))
        except json.JSONDecodeError:
            pass
print(json.dumps(commits))
")"

# ---------------------------------------------------------------------------
# Broadcast commits to Matrix
# ---------------------------------------------------------------------------
log "Broadcasting ${COMMIT_COUNT} commit(s) to ${MIGRATIONS_ROOM} (channel: ${CHANNEL})..."

python3 - <<PYEOF
import sys, json, os
sys.path.insert(0, '${SCRIPT_DIR}/../lib/matrix-client')
from matrix_client import MatrixClient

client = MatrixClient(
    homeserver=os.environ['MATRIX_HOMESERVER'],
    token=os.environ['MATRIX_BOT_TOKEN'],
)

commits_raw = json.loads('''${COMMITS_JSON}''')
# Remap to the format broadcast_commits expects
commits = [{"hash": c["hash"], "message": c["subject"], "author": c["author"]} for c in commits_raw]

client.broadcast_commits('${MIGRATIONS_ROOM}', '${REPO_NAME}', commits, channel='${CHANNEL}')
print(f"[INFO]  Commit broadcast sent ({len(commits)} commit(s)).")
PYEOF

# ---------------------------------------------------------------------------
# If migration files detected, send an alert and process manifests
# ---------------------------------------------------------------------------
if [[ "$HAS_MIGRATIONS" == "true" ]]; then
    log "Migration-related files detected. Sending alert..."

    MIGRATION_FILE_LIST="$MIGRATION_FILES"

    python3 - <<PYEOF
import sys, os
sys.path.insert(0, '${SCRIPT_DIR}/../lib/matrix-client')
from matrix_client import MatrixClient

client = MatrixClient(
    homeserver=os.environ['MATRIX_HOMESERVER'],
    token=os.environ['MATRIX_BOT_TOKEN'],
)

repo_name = '${REPO_NAME}'
room      = '${MIGRATIONS_ROOM}'
file_list = """${MIGRATION_FILE_LIST}""".strip()

lines = ["Migration-related changes detected in push to " + repo_name + ":"]
for f in file_list.splitlines():
    f = f.strip()
    if f:
        lines.append(f"  {f}")

client.send_alert(room, "warning", "\n".join(lines))
print("[INFO]  Migration alert sent.")
PYEOF

    # Broadcast any pending migration manifests
    MANIFEST_GLOB="${REPO_ROOT}/migrations/pending/*.json"
    # Use nullglob-safe expansion
    MANIFESTS=()
    while IFS= read -r -d '' manifest; do
        MANIFESTS+=("$manifest")
    done < <(find "${REPO_ROOT}/migrations/pending" -maxdepth 1 -name '*.json' -print0 2>/dev/null || true)

    if [[ ${#MANIFESTS[@]} -gt 0 ]]; then
        log "Found ${#MANIFESTS[@]} migration manifest(s). Broadcasting..."
        for manifest in "${MANIFESTS[@]}"; do
            MANIFEST_CONTENT="$(cat "$manifest")"
            MANIFEST_BASENAME="$(basename "$manifest")"
            log "  Broadcasting manifest: ${MANIFEST_BASENAME}"

            python3 - <<PYEOF
import sys, json, os
sys.path.insert(0, '${SCRIPT_DIR}/../lib/matrix-client')
from matrix_client import MatrixClient

client = MatrixClient(
    homeserver=os.environ['MATRIX_HOMESERVER'],
    token=os.environ['MATRIX_BOT_TOKEN'],
)

repo_name       = '${REPO_NAME}'
room            = '${MIGRATIONS_ROOM}'
manifest_name   = '${MANIFEST_BASENAME}'
manifest_raw    = '''${MANIFEST_CONTENT}'''

try:
    migration = json.loads(manifest_raw)
except json.JSONDecodeError as e:
    print(f"[WARN]  Could not parse manifest {manifest_name}: {e}", file=sys.stderr)
    sys.exit(0)

# Build a human-readable summary from common manifest fields
lines = [f"[{repo_name}] Migration manifest: {manifest_name}"]
for key in ("id", "name", "version", "description", "type", "author", "created_at", "target"):
    if key in migration:
        lines.append(f"  {key}: {migration[key]}")

# If there are steps/operations, count them
for steps_key in ("steps", "operations", "queries", "commands"):
    if steps_key in migration and isinstance(migration[steps_key], list):
        lines.append(f"  {steps_key}: {len(migration[steps_key])} item(s)")

text = "\n".join(lines)
client.send_alert(room, "info", text)
print(f"[INFO]  Manifest broadcast sent for {manifest_name}.")
PYEOF
        done
    else
        log "No pending migration manifests found."
    fi
fi

log "Done."
