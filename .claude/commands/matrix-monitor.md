---
name: matrix-monitor
description: Monitor Matrix rooms and respond to messages from other bots and users. Use when asked to watch Matrix, monitor rooms, or respond to bot messages.
---

# Matrix Monitor

You are now monitoring all joined Matrix rooms for new messages.

## Start Continuous Monitoring

Immediately launch the monitor as a background task:

```bash
cd /opt/project-keystone && ./scripts/matrix-monitor.sh --continuous --interval 10
```

Run this command using the Bash tool with `run_in_background: true`. The script polls every 10 seconds and only produces output when new messages arrive (silent otherwise). Check its output periodically using TaskOutput to see and act on new messages.

## When You See Messages

For each message, decide how to act:

| Message Type | Action |
|-------------|--------|
| Commit announcement | Run `git pull` if on matching channel |
| Migration required | Evaluate steps, claim work, apply if safe |
| Question from another bot | Read context, respond via SDK |
| Question from Brandon | Respond helpfully via SDK |
| Alert/incident | Investigate and respond |
| Status update | Acknowledge if relevant |

## Responding to Messages

Use the Matrix SDK to reply:

```bash
python3 -c "
import sys
sys.path.insert(0, '/opt/project-keystone/lib/matrix-client')
from matrix_client import MatrixClient

client = MatrixClient(
    homeserver='https://artemis-matrix.ecoeyetech.com',
    token='$(grep MATRIX_BOT_TOKEN /opt/project-keystone/.env | cut -d= -f2)',
)

client.send_html(
    '<ROOM_ALIAS>',
    '<PLAIN TEXT>',
    '<HTML>',
    tags={'category': 'discussion', 'project': 'project-keystone'},
)
"
```

## Credentials

- `.env` at repo root has `MATRIX_HOMESERVER` and `MATRIX_BOT_TOKEN`
- `matrix-client.conf` has non-sensitive config (channel, room, repo dir)

## Rules

- Always include your tmux session tag in responses (the SDK does this automatically)
- Use `claim_work()` before acting on migrations or incidents
- Skip messages from your own bot account
- Always invite `@brandon:artemis-matrix.ecoeyetech.com` when creating new rooms
- Use `git pushb` (never `git push`) when pushing changes
