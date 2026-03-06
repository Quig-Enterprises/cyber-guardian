"""Tests for web attack modules: XSS, CSRF, CORS, Session."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from redteam.base import AttackResult, Severity, Status
from redteam.attacks.web.xss import XSSAttack
from redteam.attacks.web.csrf import CSRFAttack
from redteam.attacks.web.cors import CORSAttack
from redteam.attacks.web.session import SessionAttack


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_mock_client(**overrides):
    """Create a mock RedTeamClient with default behaviors."""
    client = MagicMock()
    client.post = AsyncMock(return_value=(200, '{"success": true}', {"Content-Type": "application/json"}))
    client.get = AsyncMock(return_value=(200, '{"messages": []}', {"Content-Type": "application/json"}))
    client.chat = AsyncMock()
    client.base_url = "http://localhost:8081/eqmon"
    client._cookies = {"eqmon_session": "test_jwt_token"}
    for k, v in overrides.items():
        setattr(client, k, v)
    return client


# ---------------------------------------------------------------------------
# XSSAttack
# ---------------------------------------------------------------------------

class TestXSSAttackMetadata:
    def test_name(self):
        attack = XSSAttack()
        assert attack.name == "web.xss"

    def test_category(self):
        attack = XSSAttack()
        assert attack.category == "web"

    def test_severity(self):
        attack = XSSAttack()
        assert attack.severity == Severity.HIGH

    def test_has_description(self):
        attack = XSSAttack()
        assert len(attack.description) > 0


class TestXSSAttackExecution:
    @pytest.mark.asyncio
    async def test_returns_list_of_results(self):
        client = make_mock_client()
        # Simulate messages endpoint returning escaped content
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        client.get = AsyncMock(return_value=(
            200,
            '{"messages": [{"content": "&lt;script&gt;alert(\'XSS\')&lt;/script&gt;"}]}',
            {}
        ))
        attack = XSSAttack()
        results = await attack.execute(client)
        assert isinstance(results, list)
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_detects_unescaped_script_tag(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        # Response contains unescaped payload - VULNERABLE
        client.get = AsyncMock(return_value=(
            200,
            '{"messages": [{"content": "<script>alert(\'XSS\')</script>"}]}',
            {}
        ))
        attack = XSSAttack()
        results = await attack.execute(client)
        script_results = [r for r in results if r.variant == "script_tag"]
        assert len(script_results) >= 1
        assert script_results[0].status == Status.VULNERABLE

    @pytest.mark.asyncio
    async def test_detects_escaped_script_tag(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        # Response has HTML-escaped payload - DEFENDED
        client.get = AsyncMock(return_value=(
            200,
            '{"messages": [{"content": "&lt;script&gt;alert(\'XSS\')&lt;/script&gt;"}]}',
            {}
        ))
        attack = XSSAttack()
        results = await attack.execute(client)
        script_results = [r for r in results if r.variant == "script_tag"]
        assert len(script_results) >= 1
        assert script_results[0].status == Status.DEFENDED

    @pytest.mark.asyncio
    async def test_has_six_variants(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        client.get = AsyncMock(return_value=(200, '{"messages": []}', {}))
        attack = XSSAttack()
        results = await attack.execute(client)
        assert len(results) == 6

    @pytest.mark.asyncio
    async def test_score_aggregation(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        client.get = AsyncMock(return_value=(200, '{"messages": []}', {}))
        attack = XSSAttack()
        results = await attack.execute(client)
        score = attack.score(results)
        assert score.total_variants == 6
        assert score.attack_name == "web.xss"


# ---------------------------------------------------------------------------
# CSRFAttack
# ---------------------------------------------------------------------------

class TestCSRFAttackMetadata:
    def test_name(self):
        attack = CSRFAttack()
        assert attack.name == "web.csrf"

    def test_category(self):
        attack = CSRFAttack()
        assert attack.category == "web"

    def test_severity(self):
        attack = CSRFAttack()
        assert attack.severity == Severity.HIGH


class TestCSRFAttackExecution:
    @pytest.mark.asyncio
    async def test_returns_list_of_results(self):
        client = make_mock_client()
        attack = CSRFAttack()
        results = await attack.execute(client)
        assert isinstance(results, list)
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_has_three_variants(self):
        client = make_mock_client()
        attack = CSRFAttack()
        results = await attack.execute(client)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_no_origin_header_variant(self):
        client = make_mock_client()
        # Server accepts POST without Origin - VULNERABLE
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        attack = CSRFAttack()
        results = await attack.execute(client)
        no_origin = [r for r in results if r.variant == "no_origin_header"]
        assert len(no_origin) == 1

    @pytest.mark.asyncio
    async def test_forged_origin_variant(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        attack = CSRFAttack()
        results = await attack.execute(client)
        forged = [r for r in results if r.variant == "forged_origin"]
        assert len(forged) == 1

    @pytest.mark.asyncio
    async def test_no_csrf_token_variant(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        attack = CSRFAttack()
        results = await attack.execute(client)
        token = [r for r in results if r.variant == "no_csrf_token"]
        assert len(token) == 1


# ---------------------------------------------------------------------------
# CORSAttack
# ---------------------------------------------------------------------------

class TestCORSAttackMetadata:
    def test_name(self):
        attack = CORSAttack()
        assert attack.name == "web.cors"

    def test_category(self):
        attack = CORSAttack()
        assert attack.category == "web"

    def test_severity(self):
        attack = CORSAttack()
        assert attack.severity == Severity.HIGH


class TestCORSAttackExecution:
    @pytest.mark.asyncio
    async def test_returns_list_of_results(self):
        client = make_mock_client()
        attack = CORSAttack()
        results = await attack.execute(client)
        assert isinstance(results, list)
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_has_three_variants(self):
        client = make_mock_client()
        attack = CORSAttack()
        results = await attack.execute(client)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_detects_wildcard_acao_critical(self):
        """ACAO: * with credentials: true is CRITICAL."""
        client = make_mock_client()
        client.post = AsyncMock(return_value=(
            200, '',
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        ))
        attack = CORSAttack()
        results = await attack.execute(client)
        preflight = [r for r in results if r.variant == "preflight_evil_origin"]
        assert len(preflight) == 1
        assert preflight[0].status == Status.VULNERABLE
        assert preflight[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_acao_header_is_defended(self):
        """No ACAO header means CORS is not enabled - DEFENDED."""
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '', {"Content-Type": "application/json"}))
        client.get = AsyncMock(return_value=(200, '', {"Content-Type": "application/json"}))
        attack = CORSAttack()
        results = await attack.execute(client)
        for r in results:
            if "Access-Control-Allow-Origin" not in str(r.evidence):
                assert r.status == Status.DEFENDED


# ---------------------------------------------------------------------------
# SessionAttack
# ---------------------------------------------------------------------------

class TestSessionAttackMetadata:
    def test_name(self):
        attack = SessionAttack()
        assert attack.name == "web.session"

    def test_category(self):
        attack = SessionAttack()
        assert attack.category == "web"

    def test_severity(self):
        attack = SessionAttack()
        assert attack.severity == Severity.MEDIUM


class TestSessionAttackExecution:
    @pytest.mark.asyncio
    async def test_returns_list_of_results(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        assert isinstance(results, list)
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_has_three_variants(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_checks_httponly_flag(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        httponly = [r for r in results if r.variant == "httponly_flag"]
        assert len(httponly) == 1

    @pytest.mark.asyncio
    async def test_checks_secure_flag(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        secure = [r for r in results if r.variant == "secure_flag"]
        assert len(secure) == 1

    @pytest.mark.asyncio
    async def test_checks_samesite_attribute(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        samesite = [r for r in results if r.variant == "samesite_attribute"]
        assert len(samesite) == 1

    @pytest.mark.asyncio
    async def test_missing_httponly_is_vulnerable(self):
        """Set-Cookie without HttpOnly is VULNERABLE."""
        client = make_mock_client()
        # Login returns Set-Cookie without HttpOnly
        client.post = AsyncMock(return_value=(
            200, '{"success": true}',
            {"Set-Cookie": "eqmon_session=jwt_value; Path=/; Secure; SameSite=Strict"}
        ))
        attack = SessionAttack()
        results = await attack.execute(client)
        httponly = [r for r in results if r.variant == "httponly_flag"]
        assert len(httponly) == 1
        assert httponly[0].status == Status.VULNERABLE

    @pytest.mark.asyncio
    async def test_all_flags_present_is_defended(self):
        """Set-Cookie with all flags is DEFENDED."""
        client = make_mock_client()
        client.post = AsyncMock(return_value=(
            200, '{"success": true}',
            {"Set-Cookie": "eqmon_session=jwt_value; Path=/; HttpOnly; Secure; SameSite=Strict"}
        ))
        attack = SessionAttack()
        results = await attack.execute(client)
        for r in results:
            assert r.status == Status.DEFENDED
