"""pytest wrappers for API attack batteries.

Tests authentication bypass, authorization flaws, IDOR, SQL injection,
input validation, rate limiting, and error leakage on the EQMON API.

Run with:
    pytest tests/test_api_attacks.py -v
    pytest tests/test_api_attacks.py -v -k auth
"""

import pytest

pytestmark = pytest.mark.integration

from redteam.attacks.api.auth_bypass import AuthBypassAttack
from redteam.attacks.api.authz_boundaries import AuthzBoundariesAttack
from redteam.attacks.api.idor import IdorAttack
from redteam.attacks.api.injection import InjectionAttack
from redteam.attacks.api.input_validation import InputValidationAttack
from redteam.attacks.api.rate_limiting import RateLimitingAttack
from redteam.attacks.api.error_leakage import ErrorLeakageAttack


# ---------------------------------------------------------------------------
# Authentication bypass attacks
# ---------------------------------------------------------------------------

class TestAuthBypassDefense:
    """Test that unauthenticated requests are properly rejected."""

    @pytest.mark.asyncio
    async def test_auth_bypass_variants(self, authenticated_client):
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
        attack = AuthBypassAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.auth_bypass"
        assert score.category == "api"


# ---------------------------------------------------------------------------
# Authorization boundary attacks
# ---------------------------------------------------------------------------

class TestAuthzBoundariesDefense:
    """Test that role-based access control is enforced."""

    @pytest.mark.asyncio
    async def test_authz_variants(self, authenticated_client):
        attack = AuthzBoundariesAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_authz_score_summary(self, authenticated_client):
        attack = AuthzBoundariesAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.authz_boundaries"


# ---------------------------------------------------------------------------
# IDOR attacks
# ---------------------------------------------------------------------------

class TestIdorDefense:
    """Test that cross-tenant/cross-company access is blocked."""

    @pytest.mark.asyncio
    async def test_idor_variants(self, authenticated_client):
        attack = IdorAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_idor_score_summary(self, authenticated_client):
        attack = IdorAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.idor"


# ---------------------------------------------------------------------------
# SQL injection attacks
# ---------------------------------------------------------------------------

class TestInjectionDefense:
    """Test that SQL injection is properly prevented."""

    @pytest.mark.asyncio
    async def test_injection_variants(self, authenticated_client):
        attack = InjectionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_injection_score_summary(self, authenticated_client):
        attack = InjectionAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.injection"


# ---------------------------------------------------------------------------
# Input validation attacks
# ---------------------------------------------------------------------------

class TestInputValidationDefense:
    """Test that API properly validates and sanitizes input."""

    @pytest.mark.asyncio
    async def test_input_validation_variants(self, authenticated_client):
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
        attack = InputValidationAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.input_validation"


# ---------------------------------------------------------------------------
# Rate limiting attacks
# ---------------------------------------------------------------------------

class TestRateLimitingDefense:
    """Test that API rate limiting is in place."""

    @pytest.mark.asyncio
    async def test_rate_limiting_variants(self, authenticated_client):
        attack = RateLimitingAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_rate_limiting_score_summary(self, authenticated_client):
        attack = RateLimitingAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.rate_limiting"


# ---------------------------------------------------------------------------
# Error leakage attacks
# ---------------------------------------------------------------------------

class TestErrorLeakageDefense:
    """Test that error responses don't leak sensitive information."""

    @pytest.mark.asyncio
    async def test_error_leakage_variants(self, authenticated_client):
        attack = ErrorLeakageAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        for r in results:
            if r.is_vulnerable:
                pytest.xfail(
                    f"FINDING [{r.severity.value.upper()}]: {r.variant} - {r.details}"
                )

        assert score.defended == score.total_variants

    @pytest.mark.asyncio
    async def test_error_leakage_score_summary(self, authenticated_client):
        attack = ErrorLeakageAttack()
        results = await attack.execute(authenticated_client)
        score = attack.score(results)

        assert score.total_variants > 0
        assert score.attack_name == "api.error_leakage"
