import asyncio
import time
from typing import List, Optional
from security_scanner.core.models import ScanConfig, ScanResult, DetectorResult
from security_scanner.detectors.base import BaseDetector
from security_scanner.http.client import HTTPClient


class SecurityScanner:
    """
    Main orchestrator that coordinates the entire security scanning process.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.detectors: List[BaseDetector] = []
        self._initialize_detectors()

    def _initialize_detectors(self):
        """Initialize enabled detectors based on scan configuration."""
        # Import detectors only when needed to avoid circular imports
        if self.config.scan_jwt:
            from security_scanner.detectors.jwt import JWTDetector

            self.detectors.append(JWTDetector())

        if self.config.scan_headers:
            from security_scanner.detectors.headers import HeadersDetector

            self.detectors.append(HeadersDetector())

        if self.config.scan_cors:
            from security_scanner.detectors.cors import CORSDetector

            self.detectors.append(CORSDetector())

    async def scan(self, progress_callback: Optional[callable] = None) -> ScanResult:
        """
        Execute a complete security scan against the target API.

        Args:
            progress_callback: Optional callback function for progress updates

        Returns:
            ScanResult with aggregated vulnerabilities and risk assessment
        """
        start_time = time.time()
        detector_results: List[DetectorResult] = []

        # Initial progress update
        if progress_callback:
            progress_callback(
                0, f"🚀 Starting security scan for: {self.config.target_url}"
            )

        print(f"🚀 Starting security scan for: {self.config.target_url}")
        print(f"📋 Enabled detectors: {[d.get_name() for d in self.detectors]}")

        try:
            # Step 1: Test connectivity (10% progress)
            if progress_callback:
                progress_callback(10, "🔍 Testing target connectivity...")

            async with HTTPClient(self.config) as client:
                baseline_response = await client.get(self.config.target_url)

                print(
                    f"✅ Target is reachable - Status: {baseline_response.status_code}"
                )

                if progress_callback:
                    progress_callback(20, "✅ Target is reachable")

                # Step 2: Run detectors with progress updates
                total_detectors = len(self.detectors)
                for i, detector in enumerate(self.detectors):
                    detector_name = detector.get_name()

                    # Update progress for each detector
                    if progress_callback:
                        progress = 20 + (i * 60 // total_detectors)
                        progress_callback(progress, f"🔍 Running {detector_name}...")

                    print(f"🔄 Running {detector_name}...")

                    try:
                        result = await detector.scan(
                            self.config.target_url, self.config
                        )
                        detector_results.append(result)

                        vuln_count = len(result.vulnerabilities)
                        status = (
                            "✅ Passed"
                            if vuln_count == 0
                            else f"⚠️  Found {vuln_count} issues"
                        )
                        print(f"{status} - {detector_name}")

                    except Exception as e:
                        error_result = DetectorResult(
                            detector_name=detector_name,
                            vulnerabilities=[],
                            error=f"Detector failed: {str(e)}",
                        )
                        detector_results.append(error_result)
                        print(f"❌ {detector_name} failed: {str(e)}")

            # Step 3: Process results (85% progress)
            if progress_callback:
                progress_callback(85, "📊 Calculating risk scores...")

            processed_results = self._process_detector_results(detector_results)

            # Calculate overall metrics
            total_vulnerabilities = sum(
                len(result.vulnerabilities) for result in processed_results
            )
            risk_score = self._calculate_risk_score(processed_results)
            scan_duration = time.time() - start_time

            # Step 4: Finalize (95% progress)
            if progress_callback:
                progress_callback(95, "📝 Generating final report...")

            print(f"📊 Scan completed in {scan_duration:.2f}s")
            print(f"⚠️  Found {total_vulnerabilities} vulnerabilities")
            print(f"🎯 Overall risk score: {risk_score:.1f}/10.0")

            # Step 5: Complete (100% progress)
            if progress_callback:
                progress_callback(100, "✅ Scan completed!")

            return ScanResult(
                target_url=self.config.target_url,
                scan_config=self.config,
                detector_results=processed_results,
                total_vulnerabilities=total_vulnerabilities,
                risk_score=risk_score,
                scan_duration=scan_duration,
            )

        except Exception as e:
            if progress_callback:
                progress_callback(100, f"❌ Scan failed: {str(e)}")
            print(f"❌ Scan failed: {str(e)}")
            raise

    def _process_detector_results(
        self, results: List[DetectorResult]
    ) -> List[DetectorResult]:
        """Process detector results and handle any exceptions."""
        processed = []

        for i, result in enumerate(results):
            detector_name = self.detectors[i].get_name()

            if isinstance(result, Exception):
                processed.append(
                    DetectorResult(
                        detector_name=detector_name,
                        vulnerabilities=[],
                        error=f"Detector failed: {str(result)}",
                    )
                )
            else:
                processed.append(result)

        return processed

    def _calculate_risk_score(self, results: List[DetectorResult]) -> float:
        """Calculate overall risk score based on vulnerability severity."""
        severity_weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5}

        total_score = 0.0
        vulnerability_count = 0

        for result in results:
            for vulnerability in result.vulnerabilities:
                weight = severity_weights.get(vulnerability.severity.value, 0.0)
                total_score += weight
                vulnerability_count += 1

        if vulnerability_count > 0:
            risk_score = min(10.0, total_score / vulnerability_count)
        else:
            risk_score = 0.0

        return risk_score


# Factory function for easy scanner creation
def create_security_scanner(config: ScanConfig) -> SecurityScanner:
    """Create and return a configured security scanner instance."""
    return SecurityScanner(config)
