# Task 10: Test User Setup & Database Cleanup

Create the test user lifecycle scripts and database cleanup module. These ensure repeatable test runs by creating known test accounts before testing and removing all test artifacts afterward.

## Files

- `scripts/setup_test_users.py` - Create test users in PostgreSQL with bcrypt hashing
- `scripts/teardown_test_users.py` - Remove test users and all their data
- `redteam/cleanup/db.py` - Reusable database cleanup module for the framework

---

## Step 1: Create scripts/ directory

```bash
cd /opt/security-red-team
mkdir -p scripts
```

---

## Step 2: Write scripts/setup_test_users.py

Create `/opt/security-red-team/scripts/setup_test_users.py`:

```python
#!/usr/bin/env python3
"""Create test users for security red team testing.

This script creates two test users in the eqmon PostgreSQL database:
1. A system-admin user for full-access testing
2. A viewer user for privilege escalation testing

Passwords are hashed with bcrypt to match EQMON's authentication scheme.
User IDs are prefixed with 'redteam-' for easy identification and cleanup.

Usage:
    python scripts/setup_test_users.py
    python scripts/setup_test_users.py --config config.yaml
"""

import argparse
import sys
import uuid
from pathlib import Path

import bcrypt
import psycopg2

# Add project root to path for config import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from redteam.config import load_config


# Default test users (also defined in config.yaml for reference)
TEST_USERS = [
    {
        "user_id": f"redteam-{uuid.uuid4().hex[:12]}",
        "instance_id": "default",
        "email": "redteam-sysadmin@test.com",
        "password": "RedTeam$ysAdmin2026!",
        "role": "system-admin",
        "display_name": "Red Team Admin",
    },
    {
        "user_id": f"redteam-{uuid.uuid4().hex[:12]}",
        "instance_id": "default",
        "email": "redteam-viewer@test.com",
        "password": "RedTeamV!ewer2026!",
        "role": "viewer",
        "display_name": "Red Team Viewer",
    },
]


def create_users(db_config: dict, users: list[dict] = None):
    """Create test users in the eqmon database.

    Args:
        db_config: Dict with keys: host, name, user, password
        users: List of user dicts. Defaults to TEST_USERS.
    """
    users = users or TEST_USERS

    conn = psycopg2.connect(
        host=db_config["host"],
        dbname=db_config["name"],
        user=db_config["user"],
        password=db_config["password"],
    )
    cur = conn.cursor()

    created = 0
    skipped = 0

    for user in users:
        # Check if user already exists
        cur.execute(
            "SELECT user_id FROM users WHERE email = %s AND instance_id = %s",
            (user["email"], user["instance_id"]),
        )
        if cur.fetchone():
            print(f"  SKIP: {user['email']} already exists")
            skipped += 1
            continue

        # Hash password with bcrypt
        password_hash = bcrypt.hashpw(
            user["password"].encode(), bcrypt.gensalt()
        ).decode()

        cur.execute(
            """
            INSERT INTO users (
                user_id, instance_id, email, password_hash,
                role, active, salt_version, display_name, email_verified
            )
            VALUES (%s, %s, %s, %s, %s, true, 1, %s, true)
            """,
            (
                user["user_id"],
                user["instance_id"],
                user["email"],
                password_hash,
                user["role"],
                user["display_name"],
            ),
        )
        print(f"  CREATED: {user['email']} ({user['role']}) -> {user['user_id']}")
        created += 1

    conn.commit()
    cur.close()
    conn.close()

    print(f"\nDone: {created} created, {skipped} skipped")
    return created


def main():
    parser = argparse.ArgumentParser(description="Create test users for red team testing")
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Config file path (default: config.yaml)",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    db_config = config["database"]

    print("Creating red team test users...")
    print(f"  Database: {db_config['host']}/{db_config['name']}")
    print()

    try:
        create_users(db_config)
    except psycopg2.OperationalError as e:
        print(f"\nERROR: Cannot connect to database: {e}")
        print("Is PostgreSQL running? Check config.yaml database settings.")
        sys.exit(1)
    except psycopg2.errors.UndefinedTable:
        print("\nERROR: 'users' table does not exist.")
        print("Has the eqmon database been initialized?")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## Step 3: Write scripts/teardown_test_users.py

Create `/opt/security-red-team/scripts/teardown_test_users.py`:

```python
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
    except psycopg2.errors.UndefinedTable as e:
        print(f"\nERROR: Table does not exist: {e}")
        print("Some tables may not exist yet. This is safe to ignore.")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## Step 4: Write redteam/cleanup/db.py

Create `/opt/security-red-team/redteam/cleanup/db.py`:

```python
"""Database cleanup for test artifacts.

Provides a reusable DatabaseCleaner class that removes all data created
during red team testing. Used by:
- The pytest session fixture (autouse, session-scoped)
- The CLI runner's --cleanup flag
- The teardown_test_users.py script (uses this internally)

Cleanup targets:
- ai_chat_messages created by redteam-* users
- ai_bearing_notes created by redteam-* users
- ai_chat_messages with redteam-* session IDs
"""

import logging

import psycopg2

logger = logging.getLogger(__name__)


class DatabaseCleaner:
    """Remove all test artifacts from the eqmon database."""

    def __init__(self, db_config: dict):
        """Initialize with database connection config.

        Args:
            db_config: Dict with keys: host, name, user, password
        """
        self.db_config = db_config

    def _connect(self):
        """Create a database connection."""
        return psycopg2.connect(
            host=self.db_config["host"],
            dbname=self.db_config["name"],
            user=self.db_config["user"],
            password=self.db_config["password"],
        )

    def cleanup(self, delete_users: bool = False):
        """Remove all test artifacts from the database.

        Args:
            delete_users: If True, also delete the redteam-* user accounts.
                         Defaults to False (preserve accounts for re-runs).
        """
        try:
            conn = self._connect()
        except psycopg2.OperationalError as e:
            logger.error(f"Cannot connect to database for cleanup: {e}")
            return

        cur = conn.cursor()

        try:
            # Find test user IDs
            cur.execute("SELECT user_id FROM users WHERE email LIKE 'redteam-%'")
            user_ids = [row[0] for row in cur.fetchall()]

            if not user_ids:
                logger.info("No test users found, nothing to clean")
                return

            placeholders = ",".join(["%s"] * len(user_ids))

            # Delete chat messages by user
            cur.execute(
                f"DELETE FROM ai_chat_messages WHERE user_id IN ({placeholders})",
                user_ids,
            )
            msg_count = cur.rowcount
            logger.info(f"Deleted {msg_count} chat messages")

            # Delete bearing notes by user
            cur.execute(
                f"DELETE FROM ai_bearing_notes WHERE user_id IN ({placeholders})",
                user_ids,
            )
            note_count = cur.rowcount
            logger.info(f"Deleted {note_count} bearing notes")

            # Delete messages with redteam session prefix
            cur.execute(
                "DELETE FROM ai_chat_messages WHERE session_id LIKE 'redteam-%'"
            )
            session_count = cur.rowcount
            logger.info(f"Deleted {session_count} messages with redteam session prefix")

            # Optionally delete user accounts
            user_count = 0
            if delete_users:
                cur.execute(
                    f"DELETE FROM users WHERE user_id IN ({placeholders})",
                    user_ids,
                )
                user_count = cur.rowcount
                logger.info(f"Deleted {user_count} test user accounts")

            conn.commit()
            logger.info(
                f"Cleanup complete: {msg_count} messages, {note_count} notes, "
                f"{session_count} session messages, {user_count} users"
            )

        except psycopg2.errors.UndefinedTable as e:
            logger.warning(f"Table does not exist (skipping): {e}")
            conn.rollback()
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def cleanup_session_data(self, session_prefix: str = "redteam-"):
        """Remove only chat messages matching a session prefix.

        This is a lighter cleanup for use between individual attack runs
        without touching user accounts or notes.

        Args:
            session_prefix: Session ID prefix to match (default: "redteam-")
        """
        try:
            conn = self._connect()
        except psycopg2.OperationalError as e:
            logger.error(f"Cannot connect to database for cleanup: {e}")
            return

        cur = conn.cursor()

        try:
            cur.execute(
                "DELETE FROM ai_chat_messages WHERE session_id LIKE %s",
                (f"{session_prefix}%",),
            )
            count = cur.rowcount
            conn.commit()
            logger.info(f"Deleted {count} messages with session prefix '{session_prefix}'")
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
            conn.rollback()
        finally:
            cur.close()
            conn.close()
```

---

## Step 5: Write tests for cleanup module

Add to existing test file or create `/opt/security-red-team/tests/test_cleanup.py`:

```python
"""Tests for the database cleanup module."""

import pytest
from unittest.mock import patch, MagicMock, call
from redteam.cleanup.db import DatabaseCleaner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_mock_connection(user_ids=None):
    """Create a mock psycopg2 connection with cursor."""
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    # Default: return some test user IDs
    if user_ids is None:
        user_ids = [("redteam-abc123",), ("redteam-def456",)]
    mock_cur.fetchall.return_value = user_ids
    mock_cur.rowcount = 0

    return mock_conn, mock_cur


DB_CONFIG = {
    "host": "localhost",
    "name": "eqmon",
    "user": "eqmon",
    "password": "testpass",
}


# ---------------------------------------------------------------------------
# DatabaseCleaner
# ---------------------------------------------------------------------------

class TestDatabaseCleanerInit:
    def test_stores_config(self):
        cleaner = DatabaseCleaner(DB_CONFIG)
        assert cleaner.db_config == DB_CONFIG


class TestDatabaseCleanerCleanup:
    @patch("redteam.cleanup.db.psycopg2.connect")
    def test_cleanup_deletes_messages_and_notes(self, mock_connect):
        mock_conn, mock_cur = make_mock_connection()
        mock_connect.return_value = mock_conn

        cleaner = DatabaseCleaner(DB_CONFIG)
        cleaner.cleanup()

        # Should have executed DELETE queries
        executed_queries = [
            str(c) for c in mock_cur.execute.call_args_list
        ]
        assert any("ai_chat_messages" in q for q in executed_queries)
        assert any("ai_bearing_notes" in q for q in executed_queries)
        mock_conn.commit.assert_called_once()

    @patch("redteam.cleanup.db.psycopg2.connect")
    def test_cleanup_no_users_found(self, mock_connect):
        mock_conn, mock_cur = make_mock_connection(user_ids=[])
        mock_connect.return_value = mock_conn

        cleaner = DatabaseCleaner(DB_CONFIG)
        cleaner.cleanup()

        # Should not attempt DELETE (only the SELECT was run)
        assert mock_cur.execute.call_count == 1  # Just the SELECT

    @patch("redteam.cleanup.db.psycopg2.connect")
    def test_cleanup_with_delete_users(self, mock_connect):
        mock_conn, mock_cur = make_mock_connection()
        mock_connect.return_value = mock_conn

        cleaner = DatabaseCleaner(DB_CONFIG)
        cleaner.cleanup(delete_users=True)

        executed_queries = [
            str(c) for c in mock_cur.execute.call_args_list
        ]
        # Should include a DELETE FROM users query
        assert any("DELETE" in q and "users" in q for q in executed_queries)

    @patch("redteam.cleanup.db.psycopg2.connect")
    def test_cleanup_without_delete_users(self, mock_connect):
        mock_conn, mock_cur = make_mock_connection()
        mock_connect.return_value = mock_conn

        cleaner = DatabaseCleaner(DB_CONFIG)
        cleaner.cleanup(delete_users=False)

        executed_queries = [
            str(c) for c in mock_cur.execute.call_args_list
        ]
        # DELETE FROM users should NOT appear (only ai_chat_messages and ai_bearing_notes)
        user_deletes = [
            q for q in executed_queries
            if "DELETE" in q and "users WHERE" in q
        ]
        assert len(user_deletes) == 0

    @patch("redteam.cleanup.db.psycopg2.connect")
    def test_cleanup_handles_connection_error(self, mock_connect):
        import psycopg2
        mock_connect.side_effect = psycopg2.OperationalError("Connection refused")

        cleaner = DatabaseCleaner(DB_CONFIG)
        # Should not raise
        cleaner.cleanup()

    @patch("redteam.cleanup.db.psycopg2.connect")
    def test_cleanup_closes_connection(self, mock_connect):
        mock_conn, mock_cur = make_mock_connection()
        mock_connect.return_value = mock_conn

        cleaner = DatabaseCleaner(DB_CONFIG)
        cleaner.cleanup()

        mock_cur.close.assert_called_once()
        mock_conn.close.assert_called_once()


class TestDatabaseCleanerSessionCleanup:
    @patch("redteam.cleanup.db.psycopg2.connect")
    def test_session_cleanup_deletes_by_prefix(self, mock_connect):
        mock_conn, mock_cur = make_mock_connection()
        mock_connect.return_value = mock_conn

        cleaner = DatabaseCleaner(DB_CONFIG)
        cleaner.cleanup_session_data("redteam-xss-")

        mock_cur.execute.assert_called_once()
        call_args = mock_cur.execute.call_args
        assert "session_id LIKE" in str(call_args)
        mock_conn.commit.assert_called_once()

    @patch("redteam.cleanup.db.psycopg2.connect")
    def test_session_cleanup_default_prefix(self, mock_connect):
        mock_conn, mock_cur = make_mock_connection()
        mock_connect.return_value = mock_conn

        cleaner = DatabaseCleaner(DB_CONFIG)
        cleaner.cleanup_session_data()

        call_args = mock_cur.execute.call_args
        assert "redteam-%" in str(call_args)
```

---

## Step 6: Run tests

```bash
cd /opt/security-red-team
source venv/bin/activate
python -m pytest tests/test_cleanup.py -v
```

Expected: All tests pass.

---

## Step 7: Test scripts manually (optional, requires running database)

```bash
cd /opt/security-red-team
source venv/bin/activate

# Create test users
python scripts/setup_test_users.py

# Verify they exist
python -c "
import psycopg2
conn = psycopg2.connect(host='localhost', dbname='eqmon', user='eqmon', password='3eK4NNHxLQakuTQK5KcnB3Vz')
cur = conn.cursor()
cur.execute(\"SELECT email, role FROM users WHERE email LIKE 'redteam-%'\")
for row in cur.fetchall():
    print(f'  {row[0]} ({row[1]})')
cur.close()
conn.close()
"

# Dry-run teardown
python scripts/teardown_test_users.py --dry-run

# Actual teardown (if needed)
# python scripts/teardown_test_users.py
```

---

## Step 8: Commit

```bash
cd /opt/security-red-team
git add scripts/setup_test_users.py scripts/teardown_test_users.py redteam/cleanup/db.py tests/test_cleanup.py
git commit -m "feat: add test user lifecycle scripts and database cleanup module

- setup_test_users.py: creates redteam-sysadmin and redteam-viewer with bcrypt hashing
- teardown_test_users.py: removes test users and all associated data (--dry-run supported)
- DatabaseCleaner: reusable cleanup for chat messages, bearing notes, and session data
- Both scripts support --config flag for custom config path
- Comprehensive test suite for cleanup module with mocked psycopg2"
```

---

## Acceptance Criteria

- [ ] `scripts/` directory exists
- [ ] `scripts/setup_test_users.py` creates two test users with bcrypt password hashing
- [ ] Setup script checks for existing users and skips duplicates
- [ ] Setup script uses `redteam-` prefix for user IDs
- [ ] `scripts/teardown_test_users.py` removes test users and all associated data
- [ ] Teardown script supports `--dry-run` flag
- [ ] Both scripts accept `--config` flag and use `load_config()`
- [ ] `redteam/cleanup/db.py` implements `DatabaseCleaner` with `cleanup()` and `cleanup_session_data()`
- [ ] `cleanup()` deletes chat messages, bearing notes, and session-prefixed messages
- [ ] `cleanup()` accepts `delete_users` parameter (default False)
- [ ] `cleanup()` handles connection errors gracefully (no crash)
- [ ] `tests/test_cleanup.py` covers all cleanup behaviors with mocked psycopg2
- [ ] All tests pass
- [ ] Changes committed with descriptive message
