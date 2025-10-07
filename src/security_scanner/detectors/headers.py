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


class HeadersDetector(BaseDetector):
    """Detector for security header misconfigurations."""

    def get_name(self) -> str:
        return "HeadersDetector"

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for security header vulnerabilities.

        Args:
            target_url: Target URL to scan
            config: Scan configuration

        Returns:
            DetectorResult with any found vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        async with HTTPClient(config) as client:
            try:
                response = await client.get(target_url)

                # Check for missing security headers
                missing_headers = self._check_security_headers(response.headers)

                for header, description in missing_headers:
                    vuln = Vulnerability(
                        type=f"Missing Security Header: {header}",
                        severity=Severity.MEDIUM,
                        description=f"Security header {header} is missing",
                        evidence=f"Response from {target_url} does not include {header} header",
                        remediation=f"Add {header} header to all responses. {description}",
                    )
                    vulnerabilities.append(vuln)

            except Exception as e:
                return DetectorResult(
                    detector_name=self.get_name(),
                    vulnerabilities=[],
                    error=f"Failed to scan headers: {str(e)}",
                )

        return DetectorResult(
            detector_name=self.get_name(), vulnerabilities=vulnerabilities, error=None
        )

    def _check_security_headers(self, headers: dict) -> List[tuple]:
        """
        Check for missing security headers.

        Returns:
            List of tuples (header_name, description) for missing headers
        """
        security_headers = {
            "X-Content-Type-Options": "Prevents MIME type sniffing",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-XSS-Protection": "Enables XSS protection in older browsers",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "Content-Security-Policy": "Prevents XSS and other code injection attacks",
            "Referrer-Policy": "Controls referrer information in requests",
        }

        missing = []
        for header, description in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing.append((header, description))

        return missing
