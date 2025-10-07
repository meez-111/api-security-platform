import time
from typing import List, Optional

from security_scanner.detectors.base import BaseDetector
from security_scanner.core.models import (
    DetectorResult,
    ScanConfig,
    Vulnerability,
    Severity,
)


class CORSDetector(BaseDetector):
    """
    CORS Misconfiguration Detector

    Checks for Cross-Origin Resource Sharing (CORS) misconfigurations
    that could allow unauthorized cross-domain access to API resources.
    """

    def __init__(self):
        super().__init__()
        self.name = "CORSDetector"
        self.description = (
            "Detects CORS misconfigurations and overly permissive settings"
        )
        self.supported_types = ["cors", "web_security"]

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for CORS misconfigurations in the target API.

        This implementation checks for:
        1. Overly permissive CORS origins
        2. Credential handling misconfigurations
        3. Pre-flight request vulnerabilities

        Args:
            target_url: The URL to scan for vulnerabilities
            config: Scan configuration settings

        Returns:
            DetectorResult: Contains found vulnerabilities or errors
        """
        start_time = time.time()
        vulnerabilities: List[Vulnerability] = []

        try:
            # Simulate checking CORS configurations
            # In real implementation, we'll test CORS pre-flight and actual requests
            vulnerabilities = await self._analyze_cors_configuration(target_url, config)

        except Exception as e:
            error_msg = f"CORS detector failed: {str(e)}"
            return self.create_detector_result(error=error_msg)

        scan_duration = time.time() - start_time
        result = self.create_detector_result(vulnerabilities=vulnerabilities)
        result.scan_duration = scan_duration

        return result

    async def _analyze_cors_configuration(
        self, target_url: str, config: ScanConfig
    ) -> List[Vulnerability]:
        """
        Analyze actual CORS configuration using real HTTP tests.
        """
        vulnerabilities: List[Vulnerability] = []

        try:
            from security_scanner.http.client import HTTPClient

            async with HTTPClient(config) as client:
                # First, get baseline analysis
                analysis = await client.get_response_analysis(target_url)

                if "error" in analysis:
                    return vulnerabilities

                cors_headers = analysis["cors_headers"]
                allow_origin = cors_headers.get("allow_origin")
                allow_credentials = cors_headers.get("allow_credentials")

                # Test CORS with malicious origin
                cors_test = await client.test_cors_configuration(target_url)

                if "error" not in cors_test:
                    test_origin = cors_test["test_origin"]
                    options_headers = cors_test.get("options_headers", {})
                    get_headers = cors_test.get("get_headers", {})

                    tested_allow_origin = options_headers.get(
                        "access-control-allow-origin"
                    ) or get_headers.get("access-control-allow-origin")
                    tested_allow_credentials = options_headers.get(
                        "access-control-allow-credentials"
                    ) or get_headers.get("access-control-allow-credentials")

                    # Check for wildcard origin with credentials (Critical)
                    if (
                        tested_allow_origin == "*"
                        and tested_allow_credentials == "true"
                    ):
                        vulnerabilities.append(
                            self.create_vulnerability(
                                vuln_type="cors",
                                title="Overly Permissive CORS with Credentials",
                                description="CORS configuration allows any origin (*) with credentials enabled, allowing cross-domain attacks",
                                severity=Severity.CRITICAL,
                                evidence=f"Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true when testing with Origin: {test_origin}",
                                remediation="Never use wildcard (*) origin when credentials are enabled. Use specific origin validation.",
                                location="CORS Response Headers",
                            )
                        )

                    # Check for origin reflection vulnerabilities (High)
                    elif tested_allow_origin == test_origin:
                        vulnerabilities.append(
                            self.create_vulnerability(
                                vuln_type="cors",
                                title="CORS Origin Reflection Vulnerability",
                                description="CORS configuration reflects arbitrary Origin headers, allowing unauthorized domains",
                                severity=Severity.HIGH,
                                evidence=f"Access-Control-Allow-Origin reflects test origin: {test_origin}",
                                remediation="Implement strict origin validation and avoid reflecting arbitrary origins",
                                location="CORS Response Headers",
                            )
                        )

                    # Check for wildcard without credentials (Medium)
                    elif (
                        tested_allow_origin == "*"
                        and tested_allow_credentials != "true"
                    ):
                        vulnerabilities.append(
                            self.create_vulnerability(
                                vuln_type="cors",
                                title="Overly Permissive CORS Configuration",
                                description="CORS configuration allows any origin (*) which may be overly permissive",
                                severity=Severity.MEDIUM,
                                evidence="Access-Control-Allow-Origin: * (wildcard) without credentials",
                                remediation="Consider restricting allowed origins to specific domains instead of using wildcard",
                                location="CORS Response Headers",
                            )
                        )

                # If no CORS headers found but API might need them (Low)
                if (
                    not allow_origin
                    and not tested_allow_origin
                    and "/api/" in target_url
                ):
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="cors",
                            title="Missing CORS Headers on API Endpoint",
                            description="API endpoints lack CORS headers, which may block legitimate cross-origin requests",
                            severity=Severity.LOW,
                            evidence="No CORS headers found on API endpoint",
                            remediation="Implement proper CORS headers if cross-origin access is required",
                            location="API Endpoints",
                        )
                    )

        except Exception as e:
            print(f"CORS analysis error: {e}")

        return vulnerabilities


# Factory function to create CORS detector instance
def create_cors_detector() -> CORSDetector:
    """Factory function to create and return CORS detector instance"""
    return CORSDetector()
