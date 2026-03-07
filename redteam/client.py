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

    def __init__(self, base_url: str, timeout: int = 180, origin_ip: str = None):
        from urllib.parse import urlparse, urlunparse
        self._origin_ip = origin_ip
        self._host_header: Optional[str] = None

        if origin_ip:
            parsed = urlparse(base_url.rstrip("/"))
            self._host_header = parsed.hostname
            port = parsed.port
            netloc = origin_ip if not port else f"{origin_ip}:{port}"
            self.base_url = urlunparse(parsed._replace(netloc=netloc))
        else:
            self.base_url = base_url.rstrip("/")

        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None
        self._cookies: dict = {}
        self._request_log: list[RequestLog] = []
        self._authenticated = False

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False)
        self._session = aiohttp.ClientSession(timeout=self.timeout, connector=connector)
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
        req_headers = dict(headers or {})
        if self._host_header and "Host" not in req_headers:
            req_headers["Host"] = self._host_header
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
        req_headers = dict(headers or {})
        if self._host_header and "Host" not in req_headers:
            req_headers["Host"] = self._host_header
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
        req_headers = dict(headers or {})
        if self._host_header and "Host" not in req_headers:
            req_headers["Host"] = self._host_header
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
