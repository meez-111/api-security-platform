import time
from typing import List, Optional

from security_scanner.detectors.base import BaseDetector
from security_scanner.core.models import (
    DetectorResult,
    ScanConfig,
    Vulnerability,
    Severity,
)


class HeadersDetector(BaseDetector):
    """
    Security Headers Vulnerability Detector

    Checks for missing or misconfigured security headers that protect against
    common web vulnerabilities like XSS, clickjacking, and MIME sniffing.
    """

    def __init__(self):
        super().__init__()
        self.name = "HeadersDetector"
        self.description = "Detects missing or misconfigured security headers"
        self.supported_types = ["headers", "web_security"]

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for security header vulnerabilities in the target API.

        This implementation checks for:
        1. Missing critical security headers
        2. Misconfigured header values
        3. Information disclosure headers

        Args:
            target_url: The URL to scan for vulnerabilities
            config: Scan configuration settings

        Returns:
            DetectorResult: Contains found vulnerabilities or errors
        """
        start_time = time.time()
        vulnerabilities: List[Vulnerability] = []

        try:
            # Simulate checking security headers
            # In real implementation, we'll analyze actual HTTP responses
            vulnerabilities = await self._analyze_security_headers(target_url, config)

        except Exception as e:
            error_msg = f"Headers detector failed: {str(e)}"
            return self.create_detector_result(error=error_msg)

        scan_duration = time.time() - start_time
        result = self.create_detector_result(vulnerabilities=vulnerabilities)
        result.scan_duration = scan_duration

        return result

    async def _analyze_security_headers(
        self, target_url: str, config: ScanConfig
    ) -> List[Vulnerability]:
        """
        Analyze actual security headers from HTTP responses.
        """
        vulnerabilities: List[Vulnerability] = []

        try:
            from security_scanner.http.client import HTTPClient

            async with HTTPClient(config) as client:
                analysis = await client.get_response_analysis(target_url)

                if "error" in analysis:
                    return vulnerabilities

                headers = analysis["headers"]
                server_header = analysis.get("server", "")

                # Check for missing HSTS header (only if HTTPS)
                if (
                    target_url.startswith("https://")
                    and "strict-transport-security" not in headers
                ):
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="headers",
                            title="Missing HSTS Header",
                            description="HTTP Strict Transport Security header is missing, which could allow downgrade attacks",
                            severity=Severity.HIGH,
                            evidence="No 'Strict-Transport-Security' header found in HTTPS response",
                            remediation="Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                            location="HTTP Response Headers",
                        )
                    )

                # Check for missing Content Security Policy
                if "content-security-policy" not in headers:
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="headers",
                            title="Missing Content Security Policy",
                            description="Content-Security-Policy header is missing, increasing XSS risk",
                            severity=Severity.MEDIUM,
                            evidence="No 'Content-Security-Policy' header found",
                            remediation="Implement Content Security Policy to restrict resource loading",
                            location="HTTP Response Headers",
                        )
                    )

                # Check for missing X-Frame-Options
                if "x-frame-options" not in headers:
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="headers",
                            title="Missing X-Frame-Options Header",
                            description="X-Frame-Options header is missing, allowing clickjacking attacks",
                            severity=Severity.MEDIUM,
                            evidence="No 'X-Frame-Options' header found",
                            remediation="Add X-Frame-Options: DENY or SAMEORIGIN",
                            location="HTTP Response Headers",
                        )
                    )

                # Check for server information disclosure
                if server_header and any(
                    keyword in server_header.lower()
                    for keyword in ["version", "apache", "nginx", "iis"]
                ):
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="headers",
                            title="Server Information Disclosure",
                            description="Server header reveals version information that could help attackers",
                            severity=Severity.LOW,
                            evidence=f"Server header: {server_header}",
                            remediation="Remove or genericize Server header to avoid information disclosure",
                            location="HTTP Response Headers",
                        )
                    )

                # Check for missing X-Content-Type-Options
                if "x-content-type-options" not in headers:
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="headers",
                            title="Missing X-Content-Type-Options",
                            description="X-Content-Type-Options header is missing, allowing MIME sniffing attacks",
                            severity=Severity.LOW,
                            evidence="No 'X-Content-Type-Options' header found",
                            remediation="Add X-Content-Type-Options: nosniff",
                            location="HTTP Response Headers",
                        )
                    )

        except Exception as e:
            print(f"Headers analysis error: {e}")

        return vulnerabilities


# Factory function to create Headers detector instance
def create_headers_detector() -> HeadersDetector:
    """Factory function to create and return Headers detector instance"""
    return HeadersDetector()
