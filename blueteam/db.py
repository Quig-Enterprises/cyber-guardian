"""Database connection management."""
import psycopg2
from psycopg2.extras import RealDictCursor

_conn = None


def get_connection(config: dict) -> psycopg2.extensions.connection:
    global _conn
    if _conn is None or _conn.closed:
        db = config["database"]
        _conn = psycopg2.connect(
            host=db["host"],
            port=db.get("port", 5432),
            dbname=db["name"],
            user=db["user"],
            password=db.get("password", ""),
            cursor_factory=RealDictCursor,
        )
        _conn.autocommit = True
    return _conn


def close():
    global _conn
    if _conn and not _conn.closed:
        _conn.close()
        _conn = None
