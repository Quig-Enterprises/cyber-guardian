"""Tests for the database cleanup module."""

import pytest
from unittest.mock import patch, MagicMock
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
