"""Unit tests for RedTeamClient using mocked aiohttp."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from aiohttp import CookieJar
import aiohttp

from redteam.client import RedTeamClient, ChatResponse, RequestLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_sse_lines(*events: dict) -> list[bytes]:
    """Encode a sequence of SSE event dicts as byte lines."""
    lines = []
    for event in events:
        lines.append(f"data: {json.dumps(event)}\n".encode())
    return lines


class AsyncIteratorMock:
    """Async iterator that yields items from a list."""

    def __init__(self, items):
        self._items = iter(items)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._items)
        except StopIteration:
            raise StopAsyncIteration


def make_mock_response(status=200, text_body="", headers=None, cookies=None, sse_lines=None):
    """Build a mock aiohttp response context manager."""
    resp = MagicMock()
    resp.status = status
    resp.headers = headers or {}
    resp.cookies = cookies or {}

    async def _text():
        return text_body

    resp.text = _text

    if sse_lines is not None:
        resp.content = AsyncIteratorMock(sse_lines)

    # Make it work as an async context manager
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm, resp


# ---------------------------------------------------------------------------
# RequestLog tests
# ---------------------------------------------------------------------------

class TestRequestLog:
    def test_creation(self):
        log = RequestLog(
            method="GET",
            url="http://localhost/test",
            request_body={"key": "value"},
            request_headers={"X-Custom": "header"},
            status_code=200,
            response_body='{"ok": true}',
            response_headers={"Content-Type": "application/json"},
            duration_ms=42.5,
        )
        assert log.method == "GET"
        assert log.url == "http://localhost/test"
        assert log.status_code == 200
        assert log.duration_ms == 42.5
        assert log.timestamp > 0

    def test_timestamp_auto_set(self):
        import time
        before = time.time()
        log = RequestLog(
            method="POST", url="http://x", request_body=None,
            request_headers={}, status_code=201, response_body="",
            response_headers={}, duration_ms=1.0,
        )
        after = time.time()
        assert before <= log.timestamp <= after


# ---------------------------------------------------------------------------
# ChatResponse tests
# ---------------------------------------------------------------------------

class TestChatResponse:
    def test_construction(self):
        cr = ChatResponse(
            full_text="Hello world",
            status_messages=["Thinking...", "Analyzing..."],
            error=None,
            model="qwq:32b",
            done=True,
            duration_ms=1234.5,
        )
        assert cr.full_text == "Hello world"
        assert cr.status_messages == ["Thinking...", "Analyzing..."]
        assert cr.error is None
        assert cr.model == "qwq:32b"
        assert cr.done is True
        assert cr.duration_ms == 1234.5

    def test_error_response(self):
        cr = ChatResponse(
            full_text="",
            status_messages=[],
            error="Unauthorized",
            model=None,
            done=False,
            duration_ms=50.0,
        )
        assert cr.error == "Unauthorized"
        assert cr.done is False
        assert cr.model is None


# ---------------------------------------------------------------------------
# RedTeamClient construction tests
# ---------------------------------------------------------------------------

class TestRedTeamClientInit:
    def test_base_url_strips_trailing_slash(self):
        client = RedTeamClient("http://localhost:8081/eqmon/")
        assert client.base_url == "http://localhost:8081/eqmon"

    def test_base_url_no_slash(self):
        client = RedTeamClient("http://localhost:8081/eqmon")
        assert client.base_url == "http://localhost:8081/eqmon"

    def test_default_timeout(self):
        client = RedTeamClient("http://localhost:8081")
        assert client.timeout.total == 180

    def test_custom_timeout(self):
        client = RedTeamClient("http://localhost:8081", timeout=30)
        assert client.timeout.total == 30

    def test_initial_state(self):
        client = RedTeamClient("http://localhost:8081")
        assert client._authenticated is False
        assert client._cookies == {}
        assert client.request_log == []

    def test_login_url_construction(self):
        client = RedTeamClient("http://localhost:8081/eqmon")
        expected = "http://localhost:8081/eqmon/api/auth/login.php"
        # The login method constructs: f"{self.base_url}/api/auth/login.php"
        assert f"{client.base_url}/api/auth/login.php" == expected


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------

class TestLogin:
    @pytest.mark.asyncio
    async def test_login_success_sets_authenticated(self):
        mock_cookie = MagicMock()
        mock_cookie.key = "eqmon_session"
        mock_cookie.value = "jwt_token_value"

        cm, resp = make_mock_response(status=200, text_body='{"success": true}')
        resp.cookies = {"eqmon_session": mock_cookie}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        result = await client.login("test@example.com", "password123")

        assert result is True
        assert client._authenticated is True
        assert client._cookies["eqmon_session"] == "jwt_token_value"

    @pytest.mark.asyncio
    async def test_login_failure_returns_false(self):
        cm, resp = make_mock_response(status=401, text_body='{"error": "Invalid credentials"}')
        resp.cookies = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        result = await client.login("bad@example.com", "wrong")

        assert result is False
        assert client._authenticated is False
        assert client._cookies == {}

    @pytest.mark.asyncio
    async def test_login_masks_password_in_log(self):
        cm, resp = make_mock_response(status=200, text_body='{"success": true}')
        resp.cookies = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        await client.login("user@example.com", "super_secret")

        assert len(client.request_log) == 1
        log = client.request_log[0]
        assert log.request_body["password"] == "***"
        assert log.request_body["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_login_posts_to_correct_url(self):
        cm, resp = make_mock_response(status=200, text_body='{}')
        resp.cookies = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        await client.login("u@e.com", "p")

        called_url = client._session.post.call_args[0][0]
        assert called_url == "http://localhost:8081/eqmon/api/auth/login.php"


# ---------------------------------------------------------------------------
# Cookie passing tests
# ---------------------------------------------------------------------------

class TestCookiePassing:
    @pytest.mark.asyncio
    async def test_get_uses_session_cookies_after_login(self):
        # Set up a client with stored cookies
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._cookies = {"eqmon_session": "my_jwt"}

        cm, resp = make_mock_response(status=200, text_body='{"data": []}')
        client._session = MagicMock()
        client._session.get = MagicMock(return_value=cm)

        await client.get("/api/some_endpoint.php")

        call_kwargs = client._session.get.call_args[1]
        assert call_kwargs["cookies"] == {"eqmon_session": "my_jwt"}

    @pytest.mark.asyncio
    async def test_post_uses_session_cookies_after_login(self):
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._cookies = {"eqmon_session": "my_jwt"}

        cm, resp = make_mock_response(status=200, text_body='{}')
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        await client.post("/api/some_endpoint.php", json_body={"key": "val"})

        call_kwargs = client._session.post.call_args[1]
        assert call_kwargs["cookies"] == {"eqmon_session": "my_jwt"}

    @pytest.mark.asyncio
    async def test_get_allows_cookie_override(self):
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._cookies = {"eqmon_session": "real_jwt"}

        cm, resp = make_mock_response(status=200, text_body='{}')
        client._session = MagicMock()
        client._session.get = MagicMock(return_value=cm)

        custom_cookies = {"eqmon_session": "forged_jwt"}
        await client.get("/api/endpoint.php", cookies=custom_cookies)

        call_kwargs = client._session.get.call_args[1]
        assert call_kwargs["cookies"] == {"eqmon_session": "forged_jwt"}


# ---------------------------------------------------------------------------
# SSE parsing tests
# ---------------------------------------------------------------------------

class TestSSEParsing:
    @pytest.mark.asyncio
    async def test_chat_parses_text_tokens(self):
        sse_lines = make_sse_lines(
            {"text": "Hello"},
            {"text": " "},
            {"text": "world"},
            {"done": True, "model": "qwq:32b"},
        )
        cm, resp = make_mock_response(status=200, sse_lines=sse_lines)
        resp.headers = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        result = await client.chat("Say hello")

        assert result.full_text == "Hello world"
        assert result.done is True
        assert result.model == "qwq:32b"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_chat_parses_status_messages(self):
        sse_lines = make_sse_lines(
            {"status": "Thinking..."},
            {"status": "Analyzing request..."},
            {"text": "Answer"},
            {"done": True, "model": "qwq:32b"},
        )
        cm, resp = make_mock_response(status=200, sse_lines=sse_lines)
        resp.headers = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        result = await client.chat("Think about this")

        assert result.status_messages == ["Thinking...", "Analyzing request..."]
        assert result.full_text == "Answer"

    @pytest.mark.asyncio
    async def test_chat_parses_error_event(self):
        sse_lines = make_sse_lines(
            {"error": "Model overloaded"},
        )
        cm, resp = make_mock_response(status=200, sse_lines=sse_lines)
        resp.headers = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        result = await client.chat("Trigger error")

        assert result.error == "Model overloaded"
        assert result.full_text == ""
        assert result.done is False

    @pytest.mark.asyncio
    async def test_chat_skips_non_data_lines(self):
        # Mix in blank lines and comment lines which SSE allows
        lines = [
            b"\n",
            b": this is a comment\n",
            b"data: {\"text\": \"Hi\"}\n",
            b"\n",
            b"data: {\"done\": true, \"model\": \"qwq:32b\"}\n",
        ]
        cm, resp = make_mock_response(status=200, sse_lines=lines)
        resp.headers = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        result = await client.chat("Test")

        assert result.full_text == "Hi"
        assert result.done is True

    @pytest.mark.asyncio
    async def test_chat_skips_invalid_json(self):
        lines = [
            b"data: not-valid-json\n",
            b"data: {\"text\": \"Valid\"}\n",
            b"data: {\"done\": true, \"model\": \"qwq:32b\"}\n",
        ]
        cm, resp = make_mock_response(status=200, sse_lines=lines)
        resp.headers = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        result = await client.chat("Test")

        assert result.full_text == "Valid"
        assert result.done is True

    @pytest.mark.asyncio
    async def test_chat_non_200_returns_error(self):
        cm, resp = make_mock_response(status=401, text_body="Unauthorized")
        resp.headers = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        result = await client.chat("Test")

        assert result.error == "Unauthorized"
        assert result.done is False
        assert result.full_text == ""

    @pytest.mark.asyncio
    async def test_chat_includes_session_id_in_body(self):
        sse_lines = make_sse_lines({"done": True, "model": "qwq:32b"})
        cm, resp = make_mock_response(status=200, sse_lines=sse_lines)
        resp.headers = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        await client.chat("Hello", session_id="redteam-001")

        call_kwargs = client._session.post.call_args[1]
        assert call_kwargs["json"]["session_id"] == "redteam-001"
        assert call_kwargs["json"]["action"] == "send_message"

    @pytest.mark.asyncio
    async def test_chat_includes_analysis_id_in_body(self):
        sse_lines = make_sse_lines({"done": True, "model": "qwq:32b"})
        cm, resp = make_mock_response(status=200, sse_lines=sse_lines)
        resp.headers = {}

        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        await client.chat("Hello", analysis_id="analysis-42")

        call_kwargs = client._session.post.call_args[1]
        assert call_kwargs["json"]["analysis_id"] == "analysis-42"


# ---------------------------------------------------------------------------
# Request log tests
# ---------------------------------------------------------------------------

class TestRequestLogAccumulation:
    @pytest.mark.asyncio
    async def test_get_appends_to_log(self):
        cm, resp = make_mock_response(status=200, text_body="ok")
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.get = MagicMock(return_value=cm)

        await client.get("/api/test.php")

        assert len(client.request_log) == 1
        assert client.request_log[0].method == "GET"
        assert client.request_log[0].status_code == 200

    @pytest.mark.asyncio
    async def test_post_appends_to_log(self):
        cm, resp = make_mock_response(status=201, text_body='{"id": 1}')
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        await client.post("/api/create.php", json_body={"name": "test"})

        assert len(client.request_log) == 1
        assert client.request_log[0].method == "POST"
        assert client.request_log[0].status_code == 201

    @pytest.mark.asyncio
    async def test_clear_log(self):
        cm, resp = make_mock_response(status=200, text_body="ok")
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.get = MagicMock(return_value=cm)

        await client.get("/api/test.php")
        assert len(client.request_log) == 1

        client.clear_log()
        assert len(client.request_log) == 0

    @pytest.mark.asyncio
    async def test_log_captures_url(self):
        cm, resp = make_mock_response(status=200, text_body="ok")
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.get = MagicMock(return_value=cm)

        await client.get("/api/specific_endpoint.php")

        assert client.request_log[0].url == "http://localhost:8081/eqmon/api/specific_endpoint.php"

    @pytest.mark.asyncio
    async def test_log_captures_duration(self):
        cm, resp = make_mock_response(status=200, text_body="ok")
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.get = MagicMock(return_value=cm)

        await client.get("/api/test.php")

        assert client.request_log[0].duration_ms >= 0


# ---------------------------------------------------------------------------
# chat_raw tests
# ---------------------------------------------------------------------------

class TestChatRaw:
    @pytest.mark.asyncio
    async def test_chat_raw_returns_tuple(self):
        cm, resp = make_mock_response(status=200, text_body="data: stream...")
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        status, body, headers = await client.chat_raw("Test message")

        assert status == 200
        assert body == "data: stream..."

    @pytest.mark.asyncio
    async def test_chat_raw_uses_custom_cookies(self):
        cm, resp = make_mock_response(status=200, text_body="ok")
        client = RedTeamClient("http://localhost:8081/eqmon")
        client._cookies = {"eqmon_session": "real_token"}
        client._session = MagicMock()
        client._session.post = MagicMock(return_value=cm)

        forged = {"eqmon_session": "forged_token"}
        await client.chat_raw("Test", cookies=forged)

        call_kwargs = client._session.post.call_args[1]
        assert call_kwargs["cookies"] == {"eqmon_session": "forged_token"}
