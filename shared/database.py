"""
Database utilities for Cyber-Guardian

PostgreSQL connection and query helpers.
"""

import psycopg2
import psycopg2.extras
from typing import Optional, List, Dict, Any
from contextlib import contextmanager


class Database:
    """PostgreSQL database wrapper"""

    def __init__(
        self,
        host: str,
        database: str,
        user: str,
        password: str,
        port: int = 5432
    ):
        self.connection_params = {
            "host": host,
            "database": database,
            "user": user,
            "password": password,
            "port": port
        }
        self._connection: Optional[psycopg2.extensions.connection] = None

    def connect(self) -> None:
        """Establish database connection"""
        if self._connection is None or self._connection.closed:
            self._connection = psycopg2.connect(**self.connection_params)

    def close(self) -> None:
        """Close database connection"""
        if self._connection and not self._connection.closed:
            self._connection.close()

    @contextmanager
    def cursor(self, cursor_factory=None):
        """
        Context manager for database cursor

        Example:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM users")
                results = cur.fetchall()
        """
        self.connect()
        cur = self._connection.cursor(cursor_factory=cursor_factory)
        try:
            yield cur
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cur.close()

    def execute(self, query: str, params: tuple = None) -> None:
        """Execute a query without returning results"""
        with self.cursor() as cur:
            cur.execute(query, params)

    def fetchone(self, query: str, params: tuple = None) -> Optional[Dict[str, Any]]:
        """Execute query and return one result as dict"""
        with self.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, params)
            return cur.fetchone()

    def fetchall(self, query: str, params: tuple = None) -> List[Dict[str, Any]]:
        """Execute query and return all results as list of dicts"""
        with self.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, params)
            return cur.fetchall()

    def insert(self, table: str, data: Dict[str, Any]) -> Optional[int]:
        """
        Insert row and return ID

        Args:
            table: Table name
            data: Dictionary of column: value pairs

        Returns:
            Inserted row ID if table has SERIAL primary key
        """
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["%s"] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) RETURNING id"

        with self.cursor() as cur:
            cur.execute(query, tuple(data.values()))
            result = cur.fetchone()
            return result[0] if result else None

    def update(
        self,
        table: str,
        data: Dict[str, Any],
        where: Dict[str, Any]
    ) -> int:
        """
        Update rows

        Args:
            table: Table name
            data: Dictionary of column: value pairs to update
            where: Dictionary of column: value pairs for WHERE clause

        Returns:
            Number of rows updated
        """
        set_clause = ", ".join([f"{k} = %s" for k in data.keys()])
        where_clause = " AND ".join([f"{k} = %s" for k in where.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"

        with self.cursor() as cur:
            cur.execute(query, tuple(data.values()) + tuple(where.values()))
            return cur.rowcount

    def delete(self, table: str, where: Dict[str, Any]) -> int:
        """
        Delete rows

        Args:
            table: Table name
            where: Dictionary of column: value pairs for WHERE clause

        Returns:
            Number of rows deleted
        """
        where_clause = " AND ".join([f"{k} = %s" for k in where.keys()])
        query = f"DELETE FROM {table} WHERE {where_clause}"

        with self.cursor() as cur:
            cur.execute(query, tuple(where.values()))
            return cur.rowcount

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Global connection cache for compatibility
_global_connection: Database | None = None


def get_connection(config: dict) -> psycopg2.extensions.connection:
    """
    Get or create global database connection.

    Compatibility function for existing blue team code.

    Args:
        config: Configuration dictionary with 'database' section

    Returns:
        PostgreSQL connection object
    """
    global _global_connection

    if _global_connection is None:
        db_config = config.get("database", {})
        _global_connection = Database(
            host=db_config.get("host", "localhost"),
            database=db_config.get("name", db_config.get("database", "")),
            user=db_config.get("user", ""),
            password=db_config.get("password", ""),
            port=db_config.get("port", 5432)
        )

    _global_connection.connect()
    return _global_connection._connection


def close():
    """Close global database connection."""
    global _global_connection
    if _global_connection:
        _global_connection.close()
        _global_connection = None
