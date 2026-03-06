# Task 03: HTTP Client

Create an async HTTP client for the red team framework that handles authentication, SSE parsing, and request logging.

## Target System Details

- Login: POST `http://localhost:8081/eqmon/api/auth/login.php` with `{"email": "...", "password": "..."}`
- Returns JWT in httpOnly cookie `eqmon_session`
- AI Chat: POST `http://localhost:8081/eqmon/api/ai_chat.php` with `{"action": "send_message", "message": "...", "session_id": "redteam-xxx"}` for general chat
- SSE streaming: responses come as `data: {"text": "token"}` lines, ending with `data: {"done": true, "model": "qwq:32b"}`
- Status events during thinking: `data: {"status": "Analyzing..."}`
- Error events: `data: {"error": "message"}`

## Files

- `redteam/client.py` - Main HTTP client
- `tests/test_client.py` - Unit tests (mock HTTP)

## Steps

1. Write `tests/test_client.py` (basic structure tests, SSE parsing tests)
2. Run: `pytest tests/test_client.py -v` - verify failures
3. Write `redteam/client.py`
4. Run: `pytest tests/test_client.py -v` - verify passes
5. Commit

## redteam/client.py

```python
"""Auth-aware async HTTP client with SSE support for EQMON API testing."""

import aiohttp
import asyncio
import json
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RequestLog:
    """Logged request/response pair for evidence."""
    method: str
    url: str
    request_body: Optional[dict]
    request_headers: dict
    status_code: int
    response_body: str
    response_headers: dict
    duration_ms: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class ChatResponse:
    """Parsed AI chat response from SSE stream."""
    full_text: str
    status_messages: list[str]
    error: Optional[str]
    model: Optional[str]
    done: bool
    duration_ms: float


class RedTeamClient:
    """HTTP client for testing EQMON API endpoints."""

    def __init__(self, base_url: str, timeout: int = 180):
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None
        self._cookies: dict = {}
        self._request_log: list[RequestLog] = []
        self._authenticated = False

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    @property
    def request_log(self) -> list[RequestLog]:
        return self._request_log

    def clear_log(self):
        self._request_log.clear()

    async def login(self, email: str, password: str) -> bool:
        """Authenticate and capture JWT cookie."""
        url = f"{self.base_url}/api/auth/login.php"
        start = time.monotonic()
        async with self._session.post(url, json={"email": email, "password": password}) as resp:
            duration = (time.monotonic() - start) * 1000
            body = await resp.text()
            self._log_request("POST", url, {"email": email, "password": "***"}, dict(resp.headers), resp.status, body, duration)

            if resp.status == 200:
                # Capture cookies
                for cookie in resp.cookies.values():
                    self._cookies[cookie.key] = cookie.value
                self._authenticated = True
                logger.info(f"Authenticated as {email}")
                return True
            logger.warning(f"Login failed: {resp.status} - {body}")
            return False

    async def get(self, path: str, params: dict = None, headers: dict = None, cookies: dict = None) -> tuple[int, str, dict]:
        """Send GET request. Returns (status_code, body, headers)."""
        url = f"{self.base_url}{path}"
        req_headers = headers or {}
        req_cookies = cookies if cookies is not None else self._cookies
        start = time.monotonic()
        async with self._session.get(url, params=params, headers=req_headers, cookies=req_cookies) as resp:
            duration = (time.monotonic() - start) * 1000
            body = await resp.text()
            self._log_request("GET", url, params, dict(resp.headers), resp.status, body, duration, req_headers)
            return resp.status, body, dict(resp.headers)

    async def post(self, path: str, json_body: dict = None, headers: dict = None, cookies: dict = None, raw_body: str = None) -> tuple[int, str, dict]:
        """Send POST request. Returns (status_code, body, headers)."""
        url = f"{self.base_url}{path}"
        req_headers = headers or {}
        req_cookies = cookies if cookies is not None else self._cookies
        start = time.monotonic()
        kwargs = {"headers": req_headers, "cookies": req_cookies}
        if raw_body is not None:
            kwargs["data"] = raw_body
            if "Content-Type" not in req_headers:
                kwargs["headers"]["Content-Type"] = "application/json"
        else:
            kwargs["json"] = json_body
        async with self._session.post(url, **kwargs) as resp:
            duration = (time.monotonic() - start) * 1000
            body = await resp.text()
            self._log_request("POST", url, json_body or {"raw": raw_body[:200] if raw_body else None}, dict(resp.headers), resp.status, body, duration, req_headers)
            return resp.status, body, dict(resp.headers)

    async def delete(self, path: str, params: dict = None, headers: dict = None, cookies: dict = None) -> tuple[int, str, dict]:
        """Send DELETE request."""
        url = f"{self.base_url}{path}"
        req_headers = headers or {}
        req_cookies = cookies if cookies is not None else self._cookies
        start = time.monotonic()
        async with self._session.delete(url, params=params, headers=req_headers, cookies=req_cookies) as resp:
            duration = (time.monotonic() - start) * 1000
            body = await resp.text()
            self._log_request("DELETE", url, params, dict(resp.headers), resp.status, body, duration, req_headers)
            return resp.status, body, dict(resp.headers)

    async def chat(self, message: str, session_id: str = None, analysis_id: str = None) -> ChatResponse:
        """Send a chat message and parse the SSE response stream."""
        url = f"{self.base_url}/api/ai_chat.php"
        body = {"action": "send_message", "message": message}
        if session_id:
            body["session_id"] = session_id
        if analysis_id:
            body["analysis_id"] = analysis_id

        start = time.monotonic()
        full_text = ""
        status_messages = []
        error = None
        model = None
        done = False

        try:
            async with self._session.post(url, json=body, cookies=self._cookies) as resp:
                if resp.status != 200:
                    resp_body = await resp.text()
                    duration = (time.monotonic() - start) * 1000
                    self._log_request("POST", url, body, dict(resp.headers), resp.status, resp_body, duration)
                    return ChatResponse(
                        full_text="", status_messages=[], error=resp_body,
                        model=None, done=False, duration_ms=duration
                    )

                async for line in resp.content:
                    line = line.decode("utf-8").strip()
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]  # Strip "data: " prefix
                    try:
                        data = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    if "text" in data:
                        full_text += data["text"]
                    elif "status" in data:
                        status_messages.append(data["status"])
                    elif "error" in data:
                        error = data["error"]
                    elif "done" in data:
                        done = data["done"]
                        model = data.get("model")

        except asyncio.TimeoutError:
            error = "Request timed out"
        except Exception as e:
            error = str(e)

        duration = (time.monotonic() - start) * 1000
        self._log_request("POST (SSE)", url, body, {}, 200 if done else 500, full_text[:500], duration)

        return ChatResponse(
            full_text=full_text,
            status_messages=status_messages,
            error=error,
            model=model,
            done=done,
            duration_ms=duration,
        )

    async def chat_raw(self, message: str, session_id: str = None, analysis_id: str = None, cookies: dict = None) -> tuple[int, str, dict]:
        """Send chat message but DON'T parse SSE - return raw response. Useful for API-level attacks."""
        body = {"action": "send_message", "message": message}
        if session_id:
            body["session_id"] = session_id
        if analysis_id:
            body["analysis_id"] = analysis_id
        return await self.post("/api/ai_chat.php", json_body=body, cookies=cookies)

    def _log_request(self, method, url, req_body, resp_headers, status, resp_body, duration, req_headers=None):
        self._request_log.append(RequestLog(
            method=method, url=url, request_body=req_body,
            request_headers=req_headers or {},
            status_code=status, response_body=resp_body[:2000],
            response_headers=resp_headers, duration_ms=duration,
        ))
```

## tests/test_client.py

Write tests that:
- Test SSE parsing with mock data (create a mock aiohttp response)
- Test ChatResponse construction
- Test RequestLog creation
- Test login URL construction
- Test that cookies are passed after login

```python
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
```
