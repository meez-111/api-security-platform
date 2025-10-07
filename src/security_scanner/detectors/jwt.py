import asyncio
from typing import List
from security_scanner.core.models import (
    ScanConfig,
    Vulnerability,
    Severity,
    DetectorResult,
)
from security_scanner.detectors.base import BaseDetector
from security_scanner.http.client import HTTPClient


class JWTDetector(BaseDetector):
    """Detector for JWT security vulnerabilities."""

    def get_name(self) -> str:
        return "JWTDetector"

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for JWT-related vulnerabilities.

        Args:
            target_url: Target URL to scan
            config: Scan configuration

        Returns:
            DetectorResult with any found vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        # Test for common JWT endpoints
        jwt_endpoints = [
            "/api/auth/login",
            "/api/auth/token",
            "/api/login",
            "/auth",
            "/token",
        ]

        async with HTTPClient(config) as client:
            for endpoint in jwt_endpoints:
                test_url = f"{target_url.rstrip('/')}{endpoint}"

                try:
                    response = await client.get(test_url)

                    # Check if endpoint exists and might be JWT-related
                    if response.status_code in [200, 201, 400, 401]:
                        # Look for JWT indicators in response
                        if self._has_jwt_indicators(response):
                            vuln = Vulnerability(
                                type="JWT Token Exposure",
                                severity=Severity.MEDIUM,
                                description=f"Potential JWT token endpoint found at {endpoint}",
                                evidence=f"Endpoint {test_url} returns status {response.status_code} and shows JWT characteristics",
                                remediation="Ensure JWT tokens are properly secured, use short expiration times, and implement token revocation",
                            )
                            vulnerabilities.append(vuln)
                            break

                except Exception as e:
                    # Continue with other endpoints if one fails
                    continue

        return DetectorResult(
            detector_name=self.get_name(), vulnerabilities=vulnerabilities, error=None
        )

    def _has_jwt_indicators(self, response) -> bool:
        """
        Check if the response indicates JWT token usage.
        """
        if not response or not response.text:
            return False

        text = response.text.lower()
        headers = response.headers

        # Check for JWT in response body
        jwt_indicators = [
            "jwt",
            "access_token",
            "refresh_token",
            "bearer",
            "token_type",
        ]
        body_indicators = [
            indicator for indicator in jwt_indicators if indicator in text
        ]

        # Check for JWT in headers
        auth_header = headers.get("authorization", "").lower()
        header_indicators = "bearer" in auth_header

        return len(body_indicators) > 0 or header_indicators
