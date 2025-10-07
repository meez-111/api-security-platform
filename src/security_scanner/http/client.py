import asyncio
import aiohttp
import time
from typing import Dict, Any, Optional
from security_scanner.core.models import ScanConfig


class HTTPResponse:
    """
    Wrapper for aiohttp response to provide a consistent interface.
    """

    def __init__(self, aiohttp_response: aiohttp.ClientResponse, text: str):
        self.original_response = aiohttp_response
        self.status_code = aiohttp_response.status
        self.text = text
        self.headers = dict(aiohttp_response.headers)
        self.url = str(aiohttp_response.url)

    def __repr__(self):
        return f"HTTPResponse(status_code={self.status_code}, url={self.url})"


class HTTPClient:
    """
    HTTP client for making requests with rate limiting and connection pooling.
    Now includes proper response handling.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.last_request_time = 0
        self.min_request_interval = (
            0.1  # 100ms between requests (10 requests per second)
        )
        self.request_count = 0

    async def __aenter__(self):
        """Async context manager entry."""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        connector = aiohttp.TCPConnector(
            limit=10, limit_per_host=5
        )  # Connection pooling
        self.session = aiohttp.ClientSession(
            timeout=timeout, connector=connector, headers=self.config.headers or {}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
            self.session = None

    async def _respect_rate_limit(self):
        """
        Respect rate limiting to avoid overwhelming the target.
        Ensures minimum time between requests.
        """
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time

        if time_since_last_request < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last_request
            await asyncio.sleep(sleep_time)

        self.last_request_time = time.time()
        self.request_count += 1

    async def request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        """
        Make an HTTP request with rate limiting.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            **kwargs: Additional arguments for aiohttp

        Returns:
            HTTPResponse with status_code, text, and headers
        """
        if not self.session:
            raise RuntimeError("HTTPClient must be used as async context manager")

        # Respect rate limiting
        await self._respect_rate_limit()

        # Set default headers
        headers = kwargs.pop("headers", {})
        if self.config.headers:
            # Merge config headers with request-specific headers
            merged_headers = self.config.headers.copy()
            merged_headers.update(headers)
            headers = merged_headers

        print(f"🌐 HTTP {method.upper()} {url} (Request #{self.request_count})")

        try:
            # Make the request
            aiohttp_response = await self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                allow_redirects=self.config.follow_redirects,
                ssl=self.config.verify_ssl,
                **kwargs,
            )

            # Read the response text
            response_text = await aiohttp_response.text()

            # Create our wrapped response
            response = HTTPResponse(aiohttp_response, response_text)

            print(f"✅ Response: {response.status_code} - {len(response_text)} bytes")

            return response

        except aiohttp.ClientError as e:
            print(f"❌ HTTP request failed: {str(e)}")
            raise
        except asyncio.TimeoutError:
            print(f"⏰ HTTP request timed out after {self.config.timeout}s")
            raise
        except Exception as e:
            print(f"❌ Unexpected error during HTTP request: {str(e)}")
            raise

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """
        Make a GET request.

        Args:
            url: Target URL
            **kwargs: Additional arguments for aiohttp

        Returns:
            HTTPResponse
        """
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        """
        Make a POST request.

        Args:
            url: Target URL
            **kwargs: Additional arguments for aiohttp

        Returns:
            HTTPResponse
        """
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse:
        """
        Make a PUT request.

        Args:
            url: Target URL
            **kwargs: Additional arguments for aiohttp

        Returns:
            HTTPResponse
        """
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        """
        Make a DELETE request.

        Args:
            url: Target URL
            **kwargs: Additional arguments for aiohttp

        Returns:
            HTTPResponse
        """
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        """
        Make a HEAD request.

        Args:
            url: Target URL
            **kwargs: Additional arguments for aiohttp

        Returns:
            HTTPResponse
        """
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> HTTPResponse:
        """
        Make an OPTIONS request.

        Args:
            url: Target URL
            **kwargs: Additional arguments for aiohttp

        Returns:
            HTTPResponse
        """
        return await self.request("OPTIONS", url, **kwargs)

    def get_request_count(self) -> int:
        """
        Get the total number of requests made by this client instance.

        Returns:
            Number of requests made
        """
        return self.request_count
