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
