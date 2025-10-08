import asyncio
from typing import List
from security_scanner.core.models import (
    ScanConfig,
    DetectorResult,
    Vulnerability,
    Severity,
)
from security_scanner.detectors.base import BaseDetector


class CORSDetector(BaseDetector):
    """
    CORS misconfiguration detector.
    """

    def __init__(self):
        super().__init__()
        self.name = "CORS"
        self.description = "Detects CORS misconfigurations"
        self.supported_types = [
            "cors_wildcard",
            "cors_reflection",
            "cors_credentials_with_wildcard",
        ]

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for CORS misconfigurations.
        """
        vulnerabilities = []

        try:
            # Use the HTTP client from the scanner
            from security_scanner.http.client import HTTPClient

            async with HTTPClient(config) as client:
                # Test CORS configuration
                cors_test = await client.test_cors_configuration(target_url)

                if "error" not in cors_test:
                    vulnerabilities.extend(self._analyze_cors_config(cors_test))

        except Exception as e:
            error_msg = f"CORS scan failed: {str(e)}"
            return self.create_detector_result(error=error_msg)

        return self.create_detector_result(vulnerabilities=vulnerabilities)

    def _analyze_cors_config(self, cors_test: dict) -> List[Vulnerability]:
        """Analyze CORS configuration for vulnerabilities."""
        vulnerabilities = []

        # Check for wildcard origin
        allow_origin = cors_test["get_headers"].get("access-control-allow-origin")
        allow_credentials = cors_test["get_headers"].get(
            "access-control-allow-credentials"
        )

        if allow_origin == "*":
            if allow_credentials == "true":
                # Critical: Wildcard origin with credentials
                vulnerabilities.append(
                    self.create_vulnerability(
                        vuln_type="cors_credentials_with_wildcard",
                        title="CORS Wildcard Origin with Credentials",
                        description="CORS policy allows any origin with credentials, exposing sensitive data",
                        severity=Severity.HIGH,
                        evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                        remediation="Restrict allowed origins to specific domains and avoid using credentials with wildcard",
                        location="CORS Headers",
                        cvss_score=7.5,
                    )
                )
            else:
                # Medium: Wildcard origin without credentials
                vulnerabilities.append(
                    self.create_vulnerability(
                        vuln_type="cors_wildcard",
                        title="CORS Wildcard Origin",
                        description="CORS policy allows any origin, potentially exposing APIs to cross-origin attacks",
                        severity=Severity.MEDIUM,
                        evidence="Access-Control-Allow-Origin: *",
                        remediation="Restrict allowed origins to specific trusted domains",
                        location="CORS Headers",
                        cvss_score=5.0,
                    )
                )

        return vulnerabilities
