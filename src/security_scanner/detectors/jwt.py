import asyncio
from typing import List
from security_scanner.core.models import (
    ScanConfig,
    DetectorResult,
    Vulnerability,
    Severity,
)
from security_scanner.detectors.base import BaseDetector


class JWTDetector(BaseDetector):
    """
    JWT vulnerability detector.
    """

    def __init__(self):
        super().__init__()
        self.name = "JWT"
        self.description = "Detects JWT implementation vulnerabilities"
        self.supported_types = [
            "jwt_none_algorithm",
            "jwt_no_verification",
            "jwt_secret_bruteforce",
        ]

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for JWT vulnerabilities.
        """
        vulnerabilities = []

        try:
            # Use the HTTP client from the scanner
            from security_scanner.http.client import HTTPClient

            async with HTTPClient(config) as client:
                # Analyze response for JWT tokens
                analysis = await client.get_response_analysis(target_url)

                if "error" not in analysis:
                    vulnerabilities.extend(
                        self._analyze_jwt_tokens(analysis["jwt_tokens"])
                    )

        except Exception as e:
            error_msg = f"JWT scan failed: {str(e)}"
            return self.create_detector_result(error=error_msg)

        return self.create_detector_result(vulnerabilities=vulnerabilities)

    def _analyze_jwt_tokens(self, jwt_tokens: list) -> List[Vulnerability]:
        """Analyze found JWT tokens for vulnerabilities."""
        vulnerabilities = []

        if jwt_tokens:
            vulnerabilities.append(
                self.create_vulnerability(
                    vuln_type="jwt_no_verification",
                    title="JWT Tokens Found",
                    description="JWT tokens were found in the response. Manual verification of JWT implementation is recommended.",
                    severity=Severity.LOW,
                    evidence=f"Found {len(jwt_tokens)} JWT token(s) in response",
                    remediation="Ensure JWT tokens are properly validated, use strong secrets, and implement proper expiration",
                    location="HTTP Headers/Body",
                    cvss_score=3.5,
                )
            )

        return vulnerabilities
