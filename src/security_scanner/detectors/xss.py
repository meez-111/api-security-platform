import asyncio
from typing import List
from urllib.parse import urlencode, parse_qs, urlparse

from security_scanner.core.models import (
    ScanConfig,
    DetectorResult,
    Vulnerability,
    Severity,
)
from security_scanner.detectors.base import BaseDetector


class XSSDetector(BaseDetector):
    """
    Cross-Site Scripting (XSS) vulnerability detector.
    """

    def __init__(self):
        super().__init__()
        self.name = "XSS"
        self.description = "Detects Cross-Site Scripting vulnerabilities"
        self.supported_types = ["reflected_xss"]

        # Safe XSS test payloads
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ]

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for XSS vulnerabilities.
        """
        vulnerabilities = []

        try:
            # Use the HTTP client from the scanner
            from security_scanner.http.client import HTTPClient

            async with HTTPClient(config) as client:
                # Test reflected XSS
                vulnerabilities.extend(
                    await self._test_reflected_xss(target_url, client)
                )

        except Exception as e:
            error_msg = f"XSS scan failed: {str(e)}"
            return self.create_detector_result(error=error_msg)

        return self.create_detector_result(vulnerabilities=vulnerabilities)

    async def _test_reflected_xss(self, target_url: str, client) -> List[Vulnerability]:
        """Test for reflected XSS vulnerabilities."""
        vulnerabilities = []
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)

        # If no parameters, create test parameters
        if not query_params:
            query_params = {"q": ["test"], "search": ["test"], "query": ["test"]}

        for param_name in query_params.keys():
            print(f"   Testing parameter for XSS: {param_name}")

            for payload in self.payloads[:2]:  # Test with first 2 payloads
                test_params = query_params.copy()
                test_params[param_name] = [payload]

                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"

                try:
                    response = await client.get(test_url)

                    # Check if payload is reflected without proper encoding
                    if self._is_payload_reflected(payload, response.text):
                        vuln = self.create_vulnerability(
                            vuln_type="reflected_xss",
                            title="Potential Reflected XSS",
                            description=f"Parameter '{param_name}' reflects user input without proper encoding",
                            severity=Severity.MEDIUM,
                            evidence=f"Payload '{payload}' was reflected in the response",
                            remediation="Implement proper output encoding. Use Content Security Policy (CSP). Validate and sanitize all user inputs.",
                            location=f"GET parameter: {param_name}",
                            cvss_score=6.1,
                        )
                        vulnerabilities.append(vuln)
                        break

                except Exception as e:
                    print(f"   ❌ Error testing XSS on {param_name}: {e}")

        return vulnerabilities

    def _is_payload_reflected(self, payload: str, content: str) -> bool:
        """
        Check if the XSS payload is reflected in the response without proper encoding.
        """
        # Basic reflection check
        return payload in content
