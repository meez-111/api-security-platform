import asyncio
import aiohttp
import time
from typing import List, Dict, Any, Optional, Callable
from .models import ScanConfig, ScanResult, DetectorResult, Vulnerability, Severity


class SecurityScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.detector_results: List[DetectorResult] = []

    async def scan(self, progress_callback: Optional[Callable] = None) -> ScanResult:
        """Run security scan on the target URL."""
        start_time = time.time()

        if progress_callback:
            progress_callback("Starting security scan...")

        print(f"🔍 Scanning: {self.config.target_url}")

        # Run detectors based on configuration
        detectors = []
        if self.config.scan_headers:
            detectors.append(("Security Headers", self._run_header_checks))
        if self.config.scan_cors:
            detectors.append(("CORS", self._run_cors_checks))
        if self.config.scan_jwt:
            detectors.append(("JWT", self._run_jwt_checks))
        if self.config.scan_sql_injection:
            detectors.append(("SQL Injection", self._run_sql_injection_checks))
        if self.config.scan_xss:
            detectors.append(("XSS", self._run_xss_checks))

        # Run detectors with progress updates
        for i, (detector_name, detector_func) in enumerate(detectors):
            if progress_callback:
                progress_callback(f"Running {detector_name} checks...")

            await detector_func()

            if progress_callback:
                progress = int((i + 1) / len(detectors) * 100)
                progress_callback(f"Progress: {progress}%")

        # Calculate total vulnerabilities and risk score
        total_vulnerabilities = sum(
            len(detector.vulnerabilities) for detector in self.detector_results
        )

        # Calculate risk score based on vulnerabilities
        risk_score = self._calculate_risk_score()

        scan_duration = time.time() - start_time

        if progress_callback:
            progress_callback("Scan completed!")

        return ScanResult(
            target_url=self.config.target_url,
            scan_config=self.config,
            detector_results=self.detector_results,
            total_vulnerabilities=total_vulnerabilities,
            risk_score=risk_score,
            scan_duration=scan_duration,
        )

    async def _run_header_checks(self):
        """Check for security headers vulnerabilities."""
        vulnerabilities = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.config.target_url) as response:
                    headers = response.headers

                    # Check for missing security headers
                    security_headers = [
                        "X-Content-Type-Options",
                        "X-Frame-Options",
                        "X-XSS-Protection",
                        "Strict-Transport-Security",
                    ]

                    missing_headers = [
                        header for header in security_headers if header not in headers
                    ]

                    if missing_headers:
                        vulnerabilities.append(
                            Vulnerability(
                                type="missing_security_headers",
                                severity=Severity.MEDIUM,
                                description=f"Missing security headers: {', '.join(missing_headers)}",
                                evidence=f"Response missing headers: {missing_headers}",
                                remediation="Add security headers: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, X-XSS-Protection: 1; mode=block, Strict-Transport-Security: max-age=31536000",
                            )
                        )

        except Exception as e:
            print(f"❌ Header check failed: {e}")

        self.detector_results.append(
            DetectorResult(
                detector_name="Security Headers", vulnerabilities=vulnerabilities
            )
        )

    async def _run_cors_checks(self):
        """Check for CORS misconfigurations."""
        vulnerabilities = []

        try:
            async with aiohttp.ClientSession() as session:
                # Test CORS with Origin header
                headers = {"Origin": "https://malicious.com"}
                async with session.get(
                    self.config.target_url, headers=headers
                ) as response:
                    cors_header = response.headers.get("Access-Control-Allow-Origin")

                    if cors_header == "*":
                        vulnerabilities.append(
                            Vulnerability(
                                type="cors_wildcard",
                                severity=Severity.MEDIUM,
                                description="CORS policy allows any origin",
                                evidence="Access-Control-Allow-Origin: *",
                                remediation="Restrict CORS origins to specific trusted domains",
                            )
                        )
                    elif cors_header == "https://malicious.com":
                        vulnerabilities.append(
                            Vulnerability(
                                type="cors_reflection",
                                severity=Severity.HIGH,
                                description="CORS policy reflects arbitrary Origin header",
                                evidence=f"Access-Control-Allow-Origin: {cors_header}",
                                remediation="Validate and restrict allowed origins",
                            )
                        )

        except Exception as e:
            print(f"❌ CORS check failed: {e}")

        self.detector_results.append(
            DetectorResult(detector_name="CORS", vulnerabilities=vulnerabilities)
        )

    async def _run_jwt_checks(self):
        """Check for JWT vulnerabilities."""
        # Placeholder for JWT checks
        self.detector_results.append(
            DetectorResult(detector_name="JWT", vulnerabilities=[])
        )

    async def _run_sql_injection_checks(self):
        """Check for SQL injection vulnerabilities."""
        # Placeholder for SQL injection checks
        self.detector_results.append(
            DetectorResult(detector_name="SQL Injection", vulnerabilities=[])
        )

    async def _run_xss_checks(self):
        """Check for XSS vulnerabilities."""
        # Placeholder for XSS checks
        self.detector_results.append(
            DetectorResult(detector_name="XSS", vulnerabilities=[])
        )

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score based on vulnerabilities."""
        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
        }

        total_weight = 0.0
        for detector in self.detector_results:
            for vuln in detector.vulnerabilities:
                total_weight += severity_weights.get(vuln.severity, 0.0)

        # Normalize to 0-10 scale
        return min(total_weight, 10.0)


def create_security_scanner(config: ScanConfig) -> SecurityScanner:
    """Factory function to create a security scanner."""
    return SecurityScanner(config)
