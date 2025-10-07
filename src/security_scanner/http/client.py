import asyncio
import time
from typing import Dict, Optional, Any
import httpx
from security_scanner.core.models import ScanConfig


class HTTPClient:
    """
    HTTP Client for making requests to target APIs.

    Handles session management, retries, timeouts, and rate limiting
    to be respectful of target APIs while performing security scans.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client: Optional[httpx.AsyncClient] = None
        self.request_count = 0
        self.start_time = time.time()

    async def __aenter__(self):
        """Async context manager entry"""
        self.client = httpx.AsyncClient(
            timeout=self.config.timeout,
            follow_redirects=self.config.follow_redirects,
            verify=self.config.verify_ssl,
            headers=self.config.headers,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.client:
            await self.client.aclose()

    async def get(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> httpx.Response:
        """
        Send a GET request to the target URL.

        Args:
            url: Target URL to scan
            headers: Optional custom headers

        Returns:
            HTTP response object
        """
        return await self._make_request("GET", url, headers=headers)

    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """
        Send a POST request to the target URL.

        Args:
            url: Target URL to scan
            data: POST data to send
            headers: Optional custom headers

        Returns:
            HTTP response object
        """
        return await self._make_request("POST", url, data=data, headers=headers)

    async def options(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> httpx.Response:
        """
        Send an OPTIONS request (useful for CORS detection).

        Args:
            url: Target URL to scan
            headers: Optional custom headers

        Returns:
            HTTP response object
        """
        return await self._make_request("OPTIONS", url, headers=headers)

    async def _make_request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """
        Internal method to make HTTP requests with rate limiting and error handling.
        """
        if not self.client:
            raise RuntimeError("HTTPClient not initialized. Use async context manager.")

        # Rate limiting: don't make more than 10 requests per second
        self.request_count += 1
        elapsed = time.time() - self.start_time
        if self.request_count / elapsed > 10:  # More than 10 requests per second
            await asyncio.sleep(0.1)

        try:
            response = await self.client.request(
                method=method, url=url, json=data if data else None, headers=headers
            )
            return response

        except httpx.TimeoutException:
            raise Exception(f"Request timeout after {self.config.timeout} seconds")
        except httpx.RequestError as e:
            raise Exception(f"Request failed: {str(e)}")

    def get_response_headers(self, response: httpx.Response) -> Dict[str, str]:
        """
        Extract headers from response in a consistent format.
        """
        return dict(response.headers)

    def find_jwt_tokens(self, response: httpx.Response) -> list:
        """
        Extract JWT tokens from response headers and body.

        Args:
            response: HTTP response to analyze

        Returns:
            List of found JWT tokens
        """
        tokens = []

        # Check Authorization header
        auth_header = response.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            if self._looks_like_jwt(token):
                tokens.append(token)

        # TODO: Check response body for JWT tokens
        # This would require parsing JSON responses

        return tokens

    def _looks_like_jwt(self, token: str) -> bool:
        """
        Check if a string looks like a JWT token.

        Args:
            token: String to check

        Returns:
            True if it looks like a JWT token
        """
        # JWT tokens have 3 parts separated by dots
        parts = token.split(".")
        return len(parts) == 3 and all(part for part in parts)

    async def get_response_analysis(self, url: str) -> dict:
        """
        Get comprehensive analysis of HTTP response including headers and potential tokens.

        Args:
            url: Target URL to analyze

        Returns:
            Dictionary with response analysis
        """
        try:
            response = await self.get(url)

            analysis = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "jwt_tokens": self.find_jwt_tokens(response),
                "content_type": response.headers.get("content-type", ""),
                "server": response.headers.get("server", ""),
                "cors_headers": {
                    "allow_origin": response.headers.get("access-control-allow-origin"),
                    "allow_credentials": response.headers.get(
                        "access-control-allow-credentials"
                    ),
                    "allow_methods": response.headers.get(
                        "access-control-allow-methods"
                    ),
                },
            }

            return analysis

        except Exception as e:
            return {"error": str(e)}

    async def test_cors_configuration(
        self, url: str, test_origin: str = "https://malicious-site.com"
    ) -> dict:
        """
        Test CORS configuration by sending requests with different origins.

        Args:
            url: Target URL to test
            test_origin: Origin header to test with

        Returns:
            Dictionary with CORS test results
        """
        test_headers = {"Origin": test_origin}

        try:
            # Test OPTIONS pre-flight request
            options_response = await self.options(url, headers=test_headers)

            # Test GET request with origin
            get_response = await self.get(url, headers=test_headers)

            return {
                "options_status": options_response.status_code,
                "options_headers": dict(options_response.headers),
                "get_status": get_response.status_code,
                "get_headers": dict(get_response.headers),
                "test_origin": test_origin,
            }

        except Exception as e:
            return {"error": str(e)}
