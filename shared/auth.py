"""
Authentication client for Cyber-Guardian

Handles JWT-based authentication with the target system.
"""

import aiohttp
from typing import Optional, Dict, Any


class AuthClient:
    """JWT authentication client"""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session: Optional[aiohttp.ClientSession] = None
        self.jwt_token: Optional[str] = None
        self.user_info: Dict[str, Any] = {}

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def login(self, username: str, password: str) -> bool:
        """
        Authenticate with the target system

        Returns:
            True if authentication successful, False otherwise
        """
        if not self.session:
            raise RuntimeError("AuthClient must be used as async context manager")

        login_url = f"{self.base_url}/api/auth/login.php"
        payload = {
            "username": username,
            "password": password
        }

        try:
            async with self.session.post(login_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    self.jwt_token = data.get("token")
                    self.user_info = data.get("user", {})

                    # Extract JWT from Set-Cookie header if present
                    if "Set-Cookie" in response.headers:
                        # JWT is in httpOnly cookie, session will handle it
                        pass

                    return True
                else:
                    return False

        except Exception as e:
            print(f"Login error: {e}")
            return False

    async def request(
        self,
        method: str,
        path: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Make authenticated request

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path (without base URL)
            **kwargs: Additional arguments for aiohttp request
        """
        if not self.session:
            raise RuntimeError("AuthClient must be used as async context manager")

        url = f"{self.base_url}{path}"

        # Add Authorization header if we have a token
        headers = kwargs.get("headers", {})
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        kwargs["headers"] = headers

        return await self.session.request(method, url, **kwargs)

    async def get(self, path: str, **kwargs) -> aiohttp.ClientResponse:
        """Make authenticated GET request"""
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs) -> aiohttp.ClientResponse:
        """Make authenticated POST request"""
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs) -> aiohttp.ClientResponse:
        """Make authenticated PUT request"""
        return await self.request("PUT", path, **kwargs)

    async def delete(self, path: str, **kwargs) -> aiohttp.ClientResponse:
        """Make authenticated DELETE request"""
        return await self.request("DELETE", path, **kwargs)

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated"""
        return self.jwt_token is not None or bool(self.user_info)

    @property
    def user_id(self) -> Optional[int]:
        """Get authenticated user ID"""
        return self.user_info.get("id")

    @property
    def username(self) -> Optional[str]:
        """Get authenticated username"""
        return self.user_info.get("username")

    @property
    def role(self) -> Optional[str]:
        """Get authenticated user role"""
        return self.user_info.get("role")
