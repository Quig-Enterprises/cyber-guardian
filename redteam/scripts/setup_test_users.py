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
from shared import load_config


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


def create_users(db_config: dict, users: list = None):
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
    except Exception as e:
        if "undefined_table" in str(type(e).__name__).lower() or "UndefinedTable" in str(type(e)):
            print("\nERROR: 'users' table does not exist.")
            print("Has the eqmon database been initialized?")
            sys.exit(1)
        raise


if __name__ == "__main__":
    main()
