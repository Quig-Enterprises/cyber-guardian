"""pytest integration wrappers for web attack batteries.

The unit tests in test_web_attacks.py test attack logic with mocked clients.
These integration tests run the actual attacks against the live EQMON instance.

Run with:
    pytest tests/test_web_attacks_integration.py -v
"""

import pytest

pytestmark = pytest.mark.integration

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
        attack = XSSAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_xss_score_summary(self, authenticated_client):
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
        attack = SessionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants == 3
        assert score.attack_name == "web.session"
