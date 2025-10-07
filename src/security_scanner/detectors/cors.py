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


class CORSDetector(BaseDetector):
    """Detector for CORS misconfigurations."""

    def get_name(self) -> str:
        return "CORSDetector"

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for CORS misconfigurations.

        Args:
            target_url: Target URL to scan
            config: Scan configuration

        Returns:
            DetectorResult with any found vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        async with HTTPClient(config) as client:
            try:
                # Test OPTIONS request for CORS headers
                response = await client.options(target_url)

                # Check CORS headers
                cors_vulnerabilities = self._check_cors_headers(
                    response.headers, target_url
                )
                vulnerabilities.extend(cors_vulnerabilities)

            except Exception as e:
                # Try with GET if OPTIONS fails
                try:
                    response = await client.get(target_url)
                    cors_vulnerabilities = self._check_cors_headers(
                        response.headers, target_url
                    )
                    vulnerabilities.extend(cors_vulnerabilities)
                except Exception as e2:
                    return DetectorResult(
                        detector_name=self.get_name(),
                        vulnerabilities=[],
                        error=f"Failed to scan CORS: {str(e2)}",
                    )

        return DetectorResult(
            detector_name=self.get_name(), vulnerabilities=vulnerabilities, error=None
        )

    def _check_cors_headers(
        self, headers: dict, target_url: str
    ) -> List[Vulnerability]:
        """
        Check CORS headers for misconfigurations.
        """
        vulnerabilities = []

        # Check Access-Control-Allow-Origin
        allow_origin = headers.get("Access-Control-Allow-Origin")

        if allow_origin == "*":
            vuln = Vulnerability(
                type="CORS Misconfiguration: Wildcard Origin",
                severity=Severity.HIGH,
                description="CORS is configured to allow any origin (*)",
                evidence=f"Access-Control-Allow-Origin header is set to '*' for {target_url}",
                remediation="Restrict Access-Control-Allow-Origin to specific trusted origins instead of using wildcard",
            )
            vulnerabilities.append(vuln)

        # Check if credentials are allowed with wildcard
        allow_credentials = headers.get("Access-Control-Allow-Credentials", "").lower()
        if allow_origin == "*" and allow_credentials == "true":
            vuln = Vulnerability(
                type="CORS Misconfiguration: Credentials with Wildcard",
                severity=Severity.CRITICAL,
                description="CORS allows credentials with wildcard origin",
                evidence=f"Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true for {target_url}",
                remediation="Never allow credentials with wildcard origin. Use specific origins instead.",
            )
            vulnerabilities.append(vuln)

        return vulnerabilities
