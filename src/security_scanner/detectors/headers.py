import asyncio
from typing import List
from security_scanner.core.models import (
    ScanConfig,
    DetectorResult,
    Vulnerability,
    Severity,
)
from security_scanner.detectors.base import BaseDetector


class HeadersDetector(BaseDetector):
    """
    Security Headers vulnerability detector.
    """

    def __init__(self):
        super().__init__()
        self.name = "Security Headers"
        self.description = "Checks for missing security headers"
        self.supported_types = ["missing_security_headers", "insecure_header_config"]

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for missing or misconfigured security headers.
        """
        vulnerabilities = []

        try:
            # Use the HTTP client from the scanner
            from security_scanner.http.client import HTTPClient

            async with HTTPClient(config) as client:
                response = await client.get(target_url)

                # Analyze response headers
                header_analysis = await client.get_response_analysis(target_url)

                if "error" not in header_analysis:
                    vulnerabilities.extend(
                        self._check_security_headers(header_analysis["headers"])
                    )

        except Exception as e:
            error_msg = f"Headers scan failed: {str(e)}"
            return self.create_detector_result(error=error_msg)

        return self.create_detector_result(vulnerabilities=vulnerabilities)

    def _check_security_headers(self, headers: dict) -> List[Vulnerability]:
        """Check for missing or insecure security headers."""
        vulnerabilities = []

        # Required security headers and their recommended values
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000",  # 1 year
        }

        # Check each security header
        for header, expected_value in security_headers.items():
            if header not in headers:
                vulnerabilities.append(
                    self.create_vulnerability(
                        vuln_type="missing_security_headers",
                        title=f"Missing {header} Header",
                        description=f"The {header} security header is missing from the response",
                        severity=Severity.MEDIUM,
                        evidence=f"Response does not include {header} header",
                        remediation=f"Add {header} header with value: {expected_value}",
                        location="HTTP Response Headers",
                        cvss_score=5.3,
                    )
                )

        return vulnerabilities
