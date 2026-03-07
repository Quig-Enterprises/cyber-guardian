"""WordPress-aware HTTP client with form login, nonce management, REST/XMLRPC helpers."""

import re
import time
import logging
import xml.etree.ElementTree as ET
from typing import Optional

from redteam.client import RedTeamClient

logger = logging.getLogger(__name__)


class WordPressClient(RedTeamClient):
    """HTTP client for testing WordPress sites.

    Extends RedTeamClient with WordPress-specific capabilities:
    - Form-based login via wp-login.php
    - Nonce fetching and auto-injection for REST API
    - XML-RPC call helpers (single + multicall)
    - AJAX POST helpers (authenticated + unauthenticated)
    """

    def __init__(self, base_url: str, wp_config: dict = None, timeout: int = 180, origin_ip: str = None):
        super().__init__(base_url, timeout, origin_ip=origin_ip)
        cfg = wp_config or {}
        self.login_path = cfg.get("login_path", "/wp-login.php")
        self.rest_prefix = cfg.get("rest_prefix", "/wp-json")
        self.xmlrpc_path = cfg.get("xmlrpc_path", "/xmlrpc.php")
        self.admin_path = cfg.get("admin_path", "/wp-admin")
        self.cron_path = cfg.get("cron_path", "/wp-cron.php")
        self.content_path = cfg.get("content_path", "/wp-content")
        self._wp_nonce: Optional[str] = None
        self._wp_logged_in = False

    # ------------------------------------------------------------------
    # Form-based WordPress login
    # ------------------------------------------------------------------
    async def wp_login(self, username: str, password: str) -> bool:
        """Authenticate via wp-login.php form POST.

        Captures wordpress_logged_in_* and wordpress_sec_* cookies.
        Returns True on successful login.
        """
        url = f"{self.base_url}{self.login_path}"
        form_data = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{self.base_url}{self.admin_path}/",
            "testcookie": "1",
        }

        start = time.monotonic()
        try:
            async with self._session.post(
                url,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=False,
            ) as resp:
                duration = (time.monotonic() - start) * 1000
                body = await resp.text()
                self._log_request(
                    "POST", url,
                    {"log": username, "pwd": "***"},
                    dict(resp.headers), resp.status, body[:500], duration,
                )

                # Capture all wordpress cookies
                for cookie in resp.cookies.values():
                    self._cookies[cookie.key] = cookie.value

                # WordPress redirects (302) on successful login
                is_logged_in = (
                    resp.status in (302, 303)
                    or any(k.startswith("wordpress_logged_in") for k in self._cookies)
                )
                self._wp_logged_in = is_logged_in
                if is_logged_in:
                    logger.info(f"WordPress login successful as {username}")
                    # Try to fetch nonce immediately
                    await self.fetch_nonce()
                else:
                    logger.warning(f"WordPress login failed: {resp.status}")
                return is_logged_in
        except Exception as e:
            logger.error(f"WordPress login error: {e}")
            return False

    # ------------------------------------------------------------------
    # Nonce management
    # ------------------------------------------------------------------
    async def fetch_nonce(self) -> Optional[str]:
        """Fetch a WordPress REST API nonce via wp-admin/admin-ajax.php.

        Falls back to scraping wp-admin page for _wpnonce.
        """
        # Method 1: AJAX rest-nonce action
        try:
            status, body, headers = await self.post(
                f"{self.admin_path}/admin-ajax.php",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                raw_body="action=rest-nonce",
            )
            if status == 200 and body and len(body) < 50 and body.strip() != "0":
                self._wp_nonce = body.strip()
                logger.debug(f"Got REST nonce via AJAX: {self._wp_nonce}")
                return self._wp_nonce
        except Exception:
            pass

        # Method 2: Scrape from wp-admin dashboard
        try:
            status, body, headers = await self.get(f"{self.admin_path}/")
            nonce_match = re.search(r'"wpApiSettings"\s*,\s*{[^}]*"nonce"\s*:\s*"([a-f0-9]+)"', body)
            if not nonce_match:
                nonce_match = re.search(r'_wpnonce["\s:=]+([a-f0-9]{10})', body)
            if nonce_match:
                self._wp_nonce = nonce_match.group(1)
                logger.debug(f"Got nonce from admin page: {self._wp_nonce}")
                return self._wp_nonce
        except Exception:
            pass

        logger.warning("Failed to fetch WordPress nonce")
        return None

    # ------------------------------------------------------------------
    # REST API helpers
    # ------------------------------------------------------------------
    async def rest_get(self, endpoint: str, params: dict = None,
                       headers: dict = None, authenticated: bool = True) -> tuple[int, str, dict]:
        """GET a WordPress REST API endpoint with optional nonce auth."""
        path = f"{self.rest_prefix}{endpoint}"
        req_headers = dict(headers or {})
        if authenticated and self._wp_nonce:
            req_headers["X-WP-Nonce"] = self._wp_nonce
        cookies = self._cookies if authenticated else {}
        return await self.get(path, params=params, headers=req_headers, cookies=cookies)

    async def rest_post(self, endpoint: str, json_body: dict = None,
                        headers: dict = None, authenticated: bool = True) -> tuple[int, str, dict]:
        """POST to a WordPress REST API endpoint with optional nonce auth."""
        path = f"{self.rest_prefix}{endpoint}"
        req_headers = dict(headers or {})
        if authenticated and self._wp_nonce:
            req_headers["X-WP-Nonce"] = self._wp_nonce
        cookies = self._cookies if authenticated else {}
        return await self.post(path, json_body=json_body, headers=req_headers, cookies=cookies)

    # ------------------------------------------------------------------
    # XML-RPC helpers
    # ------------------------------------------------------------------
    def _build_xmlrpc_payload(self, method: str, params: list) -> str:
        """Build an XML-RPC request payload string."""
        param_xml = ""
        for p in params:
            if isinstance(p, str):
                param_xml += f"<param><value><string>{p}</string></value></param>"
            elif isinstance(p, int):
                param_xml += f"<param><value><int>{p}</int></value></param>"
            elif isinstance(p, list):
                items = "".join(
                    f"<value><string>{item}</string></value>" for item in p
                )
                param_xml += f"<param><value><array><data>{items}</data></array></value></param>"
            elif isinstance(p, dict):
                members = ""
                for k, v in p.items():
                    members += f"<member><name>{k}</name><value><string>{v}</string></value></member>"
                param_xml += f"<param><value><struct>{members}</struct></value></param>"
            else:
                param_xml += f"<param><value><string>{str(p)}</string></value></param>"

        return (
            '<?xml version="1.0"?>'
            f"<methodCall><methodName>{method}</methodName>"
            f"<params>{param_xml}</params></methodCall>"
        )

    async def xmlrpc_call(self, method: str, params: list = None) -> tuple[int, str, dict]:
        """Execute a single XML-RPC call."""
        payload = self._build_xmlrpc_payload(method, params or [])
        return await self.post(
            self.xmlrpc_path,
            raw_body=payload,
            headers={"Content-Type": "text/xml"},
            cookies={},
        )

    async def xmlrpc_multicall(self, calls: list[tuple[str, list]]) -> tuple[int, str, dict]:
        """Execute XML-RPC system.multicall with multiple calls batched."""
        multicall_params = []
        for method, params in calls:
            multicall_params.append({
                "methodName": method,
                "params": params if isinstance(params, list) else [params],
            })
        # Build multicall payload manually for proper struct encoding
        calls_xml = ""
        for call in multicall_params:
            method_member = f'<member><name>methodName</name><value><string>{call["methodName"]}</string></value></member>'
            params_items = ""
            for p in call["params"]:
                if isinstance(p, str):
                    params_items += f"<value><string>{p}</string></value>"
                elif isinstance(p, int):
                    params_items += f"<value><int>{p}</int></value>"
                else:
                    params_items += f"<value><string>{str(p)}</string></value>"
            params_member = f'<member><name>params</name><value><array><data>{params_items}</data></array></value></member>'
            calls_xml += f"<value><struct>{method_member}{params_member}</struct></value>"

        payload = (
            '<?xml version="1.0"?>'
            "<methodCall><methodName>system.multicall</methodName>"
            "<params><param><value><array><data>"
            f"{calls_xml}"
            "</data></array></value></param></params></methodCall>"
        )
        return await self.post(
            self.xmlrpc_path,
            raw_body=payload,
            headers={"Content-Type": "text/xml"},
            cookies={},
        )

    # ------------------------------------------------------------------
    # AJAX helpers
    # ------------------------------------------------------------------
    async def ajax_post(self, action: str, data: dict = None,
                        authenticated: bool = True) -> tuple[int, str, dict]:
        """POST to admin-ajax.php with the given action."""
        form_data = dict(data or {})
        form_data["action"] = action
        # Encode as form data
        encoded = "&".join(f"{k}={v}" for k, v in form_data.items())
        cookies = self._cookies if authenticated else {}
        return await self.post(
            f"{self.admin_path}/admin-ajax.php",
            raw_body=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            cookies=cookies,
        )

    # ------------------------------------------------------------------
    # Form POST helper
    # ------------------------------------------------------------------
    async def post_form(self, path: str, data: dict,
                        authenticated: bool = True) -> tuple[int, str, dict]:
        """POST application/x-www-form-urlencoded data."""
        encoded = "&".join(f"{k}={v}" for k, v in data.items())
        cookies = self._cookies if authenticated else {}
        return await self.post(
            path,
            raw_body=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            cookies=cookies,
        )
