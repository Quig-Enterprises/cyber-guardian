# Task 11: pytest Integration

Wrap the attack framework as pytest tests for CI-friendly execution. Each attack module gets a thin pytest wrapper that runs the attack, scores results, and reports findings via pytest's `xfail` mechanism (vulnerabilities are expected findings, not test failures).

## Files

- `tests/conftest.py` - Shared fixtures (config, authenticated client, cleanup)
- `tests/test_ai_attacks.py` - pytest wrappers for AI attack batteries
- `tests/test_api_attacks.py` - pytest wrappers for API attack batteries
- `tests/test_web_attacks.py` - Already exists from Task 09; augment with pytest integration patterns

---

## Step 1: Write tests/conftest.py

Create `/opt/security-red-team/tests/conftest.py`:

```python
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

    This fixture is session-scoped so authentication happens once for
    the entire test run. The client stays logged in across all tests.

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

    This is autouse and session-scoped, so it runs automatically.
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
    """Generate a unique session ID for a single test.

    Each test gets its own session ID to avoid message collisions
    between concurrent or sequential test runs.
    """
    return f"redteam-test-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def analysis_id(config):
    """Return the configured analysis ID for bearing-context tests."""
    return config["test_data"]["analysis_id"]


@pytest.fixture
def instance_id(config):
    """Return the configured instance ID."""
    return config["test_data"]["instance_id"]
```

---

## Step 2: Write tests/test_ai_attacks.py

Create `/opt/security-red-team/tests/test_ai_attacks.py`:

```python
"""pytest wrappers for AI attack batteries.

Each test imports an attack class, runs it against the authenticated client,
and reports findings. Vulnerabilities are marked as xfail (expected findings
for a red team tool) rather than hard failures.

Run with:
    pytest tests/test_ai_attacks.py -v
    pytest tests/test_ai_attacks.py -v --attack-category ai
    pytest tests/test_ai_attacks.py -v -k jailbreak
"""

import pytest
from redteam.attacks.ai.jailbreak import JailbreakAttack
from redteam.attacks.ai.prompt_injection import PromptInjectionAttack
from redteam.attacks.ai.extraction import ExtractionAttack
from redteam.attacks.ai.off_topic import OffTopicAttack
from redteam.attacks.ai.hallucination import HallucinationAttack


# ---------------------------------------------------------------------------
# Jailbreak attacks
# ---------------------------------------------------------------------------

class TestJailbreakDefense:
    """Test that the AI resists jailbreak attempts."""

    @pytest.mark.asyncio
    async def test_jailbreak_variants(self, authenticated_client):
        """Run all jailbreak variants and report findings."""
        attack = JailbreakAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        # Log detailed results for the report
        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        # If we get here, all variants were defended
        assert score.defended == score.total_variants, (
            f"Expected all {score.total_variants} variants defended, "
            f"got {score.defended} defended, {score.vulnerable} vulnerable"
        )

    @pytest.mark.asyncio
    async def test_jailbreak_score_summary(self, authenticated_client):
        """Verify jailbreak score aggregation works correctly."""
        attack = JailbreakAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0, "No jailbreak variants were executed"
        assert score.attack_name == "ai.jailbreak"
        assert score.category == "ai"


# ---------------------------------------------------------------------------
# Prompt injection attacks
# ---------------------------------------------------------------------------

class TestPromptInjectionDefense:
    """Test that the AI resists prompt injection attempts."""

    @pytest.mark.asyncio
    async def test_prompt_injection_variants(self, authenticated_client):
        """Run all prompt injection variants and report findings."""
        attack = PromptInjectionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_prompt_injection_score_summary(self, authenticated_client):
        """Verify prompt injection score aggregation."""
        attack = PromptInjectionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "ai.prompt_injection"


# ---------------------------------------------------------------------------
# System prompt extraction attacks
# ---------------------------------------------------------------------------

class TestExtractionDefense:
    """Test that the AI does not leak system prompt or config."""

    @pytest.mark.asyncio
    async def test_extraction_variants(self, authenticated_client):
        """Run all extraction variants and report findings."""
        attack = ExtractionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_extraction_score_summary(self, authenticated_client):
        """Verify extraction score aggregation."""
        attack = ExtractionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "ai.extraction"


# ---------------------------------------------------------------------------
# Off-topic compliance attacks
# ---------------------------------------------------------------------------

class TestOffTopicDefense:
    """Test that the AI stays on topic and refuses off-topic requests."""

    @pytest.mark.asyncio
    async def test_off_topic_variants(self, authenticated_client):
        """Run all off-topic variants and report findings."""
        attack = OffTopicAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_off_topic_score_summary(self, authenticated_client):
        """Verify off-topic score aggregation."""
        attack = OffTopicAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "ai.off_topic"


# ---------------------------------------------------------------------------
# Hallucination attacks
# ---------------------------------------------------------------------------

class TestHallucinationDefense:
    """Test that the AI does not fabricate data when none is available."""

    @pytest.mark.asyncio
    async def test_hallucination_variants(self, authenticated_client):
        """Run all hallucination variants and report findings."""
        attack = HallucinationAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_hallucination_score_summary(self, authenticated_client):
        """Verify hallucination score aggregation."""
        attack = HallucinationAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "ai.hallucination"
```

---

## Step 3: Write tests/test_api_attacks.py

Create `/opt/security-red-team/tests/test_api_attacks.py`:

```python
"""pytest wrappers for API attack batteries.

Tests authentication bypass, authorization flaws, input validation,
and rate limiting on the EQMON API endpoints.

Run with:
    pytest tests/test_api_attacks.py -v
    pytest tests/test_api_attacks.py -v -k auth
"""

import pytest
from redteam.attacks.api.auth_bypass import AuthBypassAttack
from redteam.attacks.api.authorization import AuthorizationAttack
from redteam.attacks.api.input_validation import InputValidationAttack
from redteam.attacks.api.rate_limit import RateLimitAttack


# ---------------------------------------------------------------------------
# Authentication bypass attacks
# ---------------------------------------------------------------------------

class TestAuthBypassDefense:
    """Test that unauthenticated requests are properly rejected."""

    @pytest.mark.asyncio
    async def test_auth_bypass_variants(self, authenticated_client):
        """Run all auth bypass variants and report findings."""
        attack = AuthBypassAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants, (
            f"{score.vulnerable} auth bypass vulnerabilities found"
        )

    @pytest.mark.asyncio
    async def test_auth_bypass_score_summary(self, authenticated_client):
        """Verify auth bypass score aggregation."""
        attack = AuthBypassAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.auth_bypass"
        assert score.category == "api"


# ---------------------------------------------------------------------------
# Authorization attacks
# ---------------------------------------------------------------------------

class TestAuthorizationDefense:
    """Test that role-based access control is enforced."""

    @pytest.mark.asyncio
    async def test_authorization_variants(self, authenticated_client, viewer_client):
        """Run all authorization variants.

        Note: This test needs both admin and viewer clients to test
        privilege escalation. The attack module should accept the viewer
        client for low-privilege operations.
        """
        attack = AuthorizationAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_authorization_score_summary(self, authenticated_client):
        """Verify authorization score aggregation."""
        attack = AuthorizationAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.authorization"


# ---------------------------------------------------------------------------
# Input validation attacks
# ---------------------------------------------------------------------------

class TestInputValidationDefense:
    """Test that API properly validates and sanitizes input."""

    @pytest.mark.asyncio
    async def test_input_validation_variants(self, authenticated_client):
        """Run all input validation variants and report findings."""
        attack = InputValidationAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_input_validation_score_summary(self, authenticated_client):
        """Verify input validation score aggregation."""
        attack = InputValidationAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.input_validation"


# ---------------------------------------------------------------------------
# Rate limiting attacks
# ---------------------------------------------------------------------------

class TestRateLimitDefense:
    """Test that API rate limiting is in place."""

    @pytest.mark.asyncio
    async def test_rate_limit_variants(self, authenticated_client):
        """Run all rate limit variants and report findings."""
        attack = RateLimitAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_rate_limit_score_summary(self, authenticated_client):
        """Verify rate limit score aggregation."""
        attack = RateLimitAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.rate_limit"
```

---

## Step 4: Write tests/test_web_attacks_integration.py

Create `/opt/security-red-team/tests/test_web_attacks_integration.py`:

```python
"""pytest integration wrappers for web attack batteries.

This file provides the CI-friendly pytest wrappers for the web attack
modules. The unit tests in test_web_attacks.py (from Task 09) test the
attack logic with mocked clients. These integration tests run the actual
attacks against the live EQMON instance.

Run with:
    pytest tests/test_web_attacks_integration.py -v
"""

import pytest
from redteam.attacks.web.xss import XSSAttack
from redteam.attacks.web.csrf import CSRFAttack
from redteam.attacks.web.cors import CORSAttack
from redteam.attacks.web.session import SessionAttack


# ---------------------------------------------------------------------------
# XSS attacks
# ---------------------------------------------------------------------------

class TestXSSDefense:
    """Test that stored/reflected XSS is properly sanitized."""

    @pytest.mark.asyncio
    async def test_xss_variants(self, authenticated_client):
        """Run all XSS variants and report findings."""
        attack = XSSAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants, (
            f"{score.vulnerable} XSS vulnerabilities found out of {score.total_variants} variants"
        )

    @pytest.mark.asyncio
    async def test_xss_score_summary(self, authenticated_client):
        """Verify XSS score aggregation."""
        attack = XSSAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants == 6
        assert score.attack_name == "web.xss"
        assert score.category == "web"


# ---------------------------------------------------------------------------
# CSRF attacks
# ---------------------------------------------------------------------------

class TestCSRFDefense:
    """Test that CSRF protections are in place."""

    @pytest.mark.asyncio
    async def test_csrf_variants(self, authenticated_client):
        """Run all CSRF variants and report findings."""
        attack = CSRFAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_csrf_score_summary(self, authenticated_client):
        """Verify CSRF score aggregation."""
        attack = CSRFAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants == 3
        assert score.attack_name == "web.csrf"


# ---------------------------------------------------------------------------
# CORS attacks
# ---------------------------------------------------------------------------

class TestCORSDefense:
    """Test that CORS is properly configured."""

    @pytest.mark.asyncio
    async def test_cors_variants(self, authenticated_client):
        """Run all CORS variants and report findings."""
        attack = CORSAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_cors_score_summary(self, authenticated_client):
        """Verify CORS score aggregation."""
        attack = CORSAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants == 3
        assert score.attack_name == "web.cors"


# ---------------------------------------------------------------------------
# Session cookie attacks
# ---------------------------------------------------------------------------

class TestSessionDefense:
    """Test that session cookies have proper security flags."""

    @pytest.mark.asyncio
    async def test_session_variants(self, authenticated_client):
        """Run all session security variants and report findings."""
        attack = SessionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_session_score_summary(self, authenticated_client):
        """Verify session score aggregation."""
        attack = SessionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants == 3
        assert score.attack_name == "web.session"
```

---

## Step 5: Verify test discovery

```bash
cd /opt/security-red-team
source venv/bin/activate

# Verify pytest discovers all test files
python -m pytest --collect-only tests/ 2>&1 | head -80

# Run just the unit tests (no live server needed)
python -m pytest tests/test_scoring.py tests/test_client.py tests/test_evaluators.py tests/test_cleanup.py -v
```

---

## Step 6: Commit

```bash
cd /opt/security-red-team
git add tests/conftest.py tests/test_ai_attacks.py tests/test_api_attacks.py tests/test_web_attacks_integration.py
git commit -m "feat: add pytest integration for CI-friendly red team execution

- conftest.py: session-scoped fixtures for config, authenticated client, viewer client, auto-cleanup
- Custom CLI options: --redteam-config, --no-cleanup, --attack-category
- test_ai_attacks.py: wrappers for jailbreak, prompt injection, extraction, off-topic, hallucination
- test_api_attacks.py: wrappers for auth bypass, authorization, input validation, rate limiting
- test_web_attacks_integration.py: live integration wrappers for XSS, CSRF, CORS, session tests
- All findings reported via pytest.xfail for vulnerability-as-expected-result pattern"
```

---

## Acceptance Criteria

- [ ] `tests/conftest.py` exists with session-scoped fixtures
- [ ] `authenticated_client` fixture authenticates via `client.login()` and asserts success
- [ ] `viewer_client` fixture provides a low-privilege session for privilege escalation tests
- [ ] `cleanup_after_all` fixture is autouse and session-scoped, runs `DatabaseCleaner` on teardown
- [ ] `--no-cleanup` CLI flag disables post-test cleanup
- [ ] `--redteam-config` CLI flag allows custom config path
- [ ] `test_session_id` fixture generates unique `redteam-test-*` session IDs
- [ ] `tests/test_ai_attacks.py` wraps all 5 AI attack classes
- [ ] `tests/test_api_attacks.py` wraps all 4 API attack classes
- [ ] `tests/test_web_attacks_integration.py` wraps all 4 web attack classes
- [ ] All test wrappers use `pytest.xfail()` for vulnerability findings (not hard failures)
- [ ] Each test class has both a variant test and a score summary test
- [ ] pytest can collect all test files without import errors (after all attack modules exist)
- [ ] Changes committed with descriptive message
