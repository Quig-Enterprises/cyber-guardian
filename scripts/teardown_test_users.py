#!/usr/bin/env python3
"""Remove test users and all their data from the eqmon database.

This script removes:
1. All chat messages created by redteam-* users
2. All bearing notes created by redteam-* users
3. All chat messages with redteam-* session IDs
4. All redteam-* user accounts

Usage:
    python scripts/teardown_test_users.py
    python scripts/teardown_test_users.py --config config.yaml
    python scripts/teardown_test_users.py --dry-run
"""

import argparse
import sys
from pathlib import Path

import psycopg2

# Add project root to path for config import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from redteam.config import load_config


def teardown_users(db_config: dict, dry_run: bool = False):
    """Remove all test users and their associated data.

    Args:
        db_config: Dict with keys: host, name, user, password
        dry_run: If True, show what would be deleted without deleting.
    """
    conn = psycopg2.connect(
        host=db_config["host"],
        dbname=db_config["name"],
        user=db_config["user"],
        password=db_config["password"],
    )
    cur = conn.cursor()

    # Find test user IDs
    cur.execute("SELECT user_id, email, role FROM users WHERE email LIKE 'redteam-%'")
    users = cur.fetchall()

    if not users:
        print("  No redteam test users found. Nothing to clean up.")
        cur.close()
        conn.close()
        return

    user_ids = [row[0] for row in users]
    placeholders = ",".join(["%s"] * len(user_ids))

    print(f"  Found {len(users)} test user(s):")
    for user_id, email, role in users:
        print(f"    - {email} ({role}) [{user_id}]")
    print()

    if dry_run:
        prefix = "  WOULD DELETE"
    else:
        prefix = "  DELETED"

    # Delete chat messages by user
    if dry_run:
        cur.execute(
            f"SELECT COUNT(*) FROM ai_chat_messages WHERE user_id IN ({placeholders})",
            user_ids,
        )
        msg_count = cur.fetchone()[0]
    else:
        cur.execute(
            f"DELETE FROM ai_chat_messages WHERE user_id IN ({placeholders})",
            user_ids,
        )
        msg_count = cur.rowcount
    print(f"{prefix}: {msg_count} chat messages (by user_id)")

    # Delete bearing notes by user
    if dry_run:
        cur.execute(
            f"SELECT COUNT(*) FROM ai_bearing_notes WHERE user_id IN ({placeholders})",
            user_ids,
        )
        note_count = cur.fetchone()[0]
    else:
        cur.execute(
            f"DELETE FROM ai_bearing_notes WHERE user_id IN ({placeholders})",
            user_ids,
        )
        note_count = cur.rowcount
    print(f"{prefix}: {note_count} bearing notes (by user_id)")

    # Delete messages with redteam session prefix
    if dry_run:
        cur.execute(
            "SELECT COUNT(*) FROM ai_chat_messages WHERE session_id LIKE 'redteam-%'"
        )
        session_count = cur.fetchone()[0]
    else:
        cur.execute(
            "DELETE FROM ai_chat_messages WHERE session_id LIKE 'redteam-%'"
        )
        session_count = cur.rowcount
    print(f"{prefix}: {session_count} chat messages (by session_id prefix)")

    # Delete user accounts
    if dry_run:
        user_count = len(users)
    else:
        cur.execute(
            f"DELETE FROM users WHERE user_id IN ({placeholders})",
            user_ids,
        )
        user_count = cur.rowcount
    print(f"{prefix}: {user_count} user account(s)")

    if not dry_run:
        conn.commit()

    cur.close()
    conn.close()

    print()
    if dry_run:
        print("  DRY RUN complete. No changes were made.")
    else:
        print(
            f"  Teardown complete: {msg_count} messages, {note_count} notes, "
            f"{session_count} session messages, {user_count} users removed."
        )


def main():
    parser = argparse.ArgumentParser(
        description="Remove red team test users and their data"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Config file path (default: config.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without making changes",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    db_config = config["database"]

    print("Tearing down red team test users...")
    print(f"  Database: {db_config['host']}/{db_config['name']}")
    print()

    try:
        teardown_users(db_config, dry_run=args.dry_run)
    except psycopg2.OperationalError as e:
        print(f"\nERROR: Cannot connect to database: {e}")
        sys.exit(1)
    except Exception as e:
        if "UndefinedTable" in str(type(e)):
            print(f"\nERROR: Table does not exist: {e}")
            print("Some tables may not exist yet. This is safe to ignore.")
            sys.exit(1)
        raise


if __name__ == "__main__":
    main()
