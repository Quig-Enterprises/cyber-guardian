"""Shared pytest fixtures for security red team tests.

Provides:
- config: Loaded YAML config (session-scoped)
- authenticated_client: RedTeamClient with active session (session-scoped)
- cleanup_after_all: Automatic database cleanup after all tests (session-scoped, autouse)
- test_session_id: Unique session ID per test (function-scoped)

Usage in tests:
    async def test_something(authenticated_client):
        results = await attack.execute(authenticated_client)
"""

import uuid
import pytest
import pytest_asyncio
import logging

from redteam.config import load_config
from redteam.client import RedTeamClient
from redteam.cleanup.db import DatabaseCleaner

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """Add custom CLI options for red team tests."""
    parser.addoption(
        "--redteam-config",
        action="store",
        default="config.yaml",
        help="Path to red team config file (default: config.yaml)",
    )
    parser.addoption(
        "--no-cleanup",
        action="store_true",
        default=False,
        help="Skip database cleanup after test run",
    )
    parser.addoption(
        "--attack-category",
        action="store",
        default=None,
        choices=["ai", "api", "web"],
        help="Only run attacks from this category",
    )


@pytest.fixture(scope="session")
def config(request):
    """Load the red team configuration."""
    config_path = request.config.getoption("--redteam-config")
    return load_config(config_path)


@pytest_asyncio.fixture(scope="session")
async def authenticated_client(config):
    """Create and authenticate a RedTeamClient.

    Session-scoped so authentication happens once for the entire test run.
    Asserts that login succeeds - if it fails, test users need to be
    created first with scripts/setup_test_users.py.
    """
    client = RedTeamClient(config["target"]["base_url"])
    await client.__aenter__()

    user = config["auth"]["test_users"]["system_admin"]
    success = await client.login(user["username"], user["password"])
    assert success, (
        "Failed to authenticate test user. "
        "Run 'python scripts/setup_test_users.py' first."
    )
    logger.info(f"Authenticated as {user['username']}")

    yield client

    await client.__aexit__(None, None, None)


@pytest_asyncio.fixture(scope="session")
async def viewer_client(config):
    """Create and authenticate a RedTeamClient with viewer role.

    Used for privilege escalation tests that need a low-privilege session.
    """
    client = RedTeamClient(config["target"]["base_url"])
    await client.__aenter__()

    user = config["auth"]["test_users"]["viewer"]
    success = await client.login(user["username"], user["password"])
    assert success, (
        "Failed to authenticate viewer user. "
        "Run 'python scripts/setup_test_users.py' first."
    )
    logger.info(f"Authenticated viewer as {user['username']}")

    yield client

    await client.__aexit__(None, None, None)


@pytest.fixture(scope="session", autouse=True)
def cleanup_after_all(request, config):
    """Clean up test artifacts after all tests complete.

    Autouse and session-scoped, so it runs automatically.
    Can be disabled with --no-cleanup.
    """
    yield  # Run all tests first

    if request.config.getoption("--no-cleanup"):
        logger.info("Cleanup skipped (--no-cleanup flag)")
        return

    logger.info("Running post-test database cleanup...")
    try:
        cleaner = DatabaseCleaner(config["database"])
        cleaner.cleanup(delete_users=False)
    except Exception as e:
        logger.warning(f"Cleanup failed (non-fatal): {e}")


@pytest.fixture
def test_session_id():
    """Generate a unique session ID for a single test."""
    return f"redteam-test-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def analysis_id(config):
    """Return the configured analysis ID for bearing-context tests."""
    return config["test_data"]["analysis_id"]


@pytest.fixture
def instance_id(config):
    """Return the configured instance ID."""
    return config["test_data"]["instance_id"]
