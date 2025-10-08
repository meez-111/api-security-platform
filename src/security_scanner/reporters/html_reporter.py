import os
from pathlib import Path
from typing import Optional
from datetime import datetime
from jinja2 import Template

from security_scanner.core.models import ScanResult
from .base import BaseReporter


class HTMLReporter(BaseReporter):
    """
    HTML reporter that generates professional security assessment reports
    with dark mode and interactive features.
    """

    def __init__(self):
        super().__init__()
        self.template_path = (
            Path(__file__).parent / "templates" / "security_report.html"
        )

    def generate(
        self, scan_result: ScanResult, output_path: Optional[str] = None
    ) -> str:
        """
        Generate an HTML security report from scan results.

        Args:
            scan_result: The scan results to report on
            output_path: Optional custom output path

        Returns:
            Path to the generated report file
        """
        try:
            # Generate output path if not provided
            if output_path is None:
                output_path = self._get_output_path(scan_result, "html")

            # Load and render template
            with open(self.template_path, "r", encoding="utf-8") as f:
                template_content = f.read()

            template = Template(template_content)

            # Prepare data for template
            report_data = self._prepare_report_data(scan_result)

            # Render template
            html_report = template.render(**report_data)

            # Ensure output directory exists
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Write report
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_report)

            return str(output_path)

        except Exception as e:
            raise Exception(f"Failed to generate HTML report: {str(e)}")

    def _prepare_report_data(self, scan_result: ScanResult) -> dict:
        """
        Prepare and structure data for the HTML template.
        """
        # Calculate severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # Group vulnerabilities by detector
        detector_map = {}

        # Process vulnerabilities from detector results
        vulnerabilities = []
        for detector_result in getattr(scan_result, "detector_results", []):
            detector_name = getattr(detector_result, "detector_name", "Unknown")

            # Add vulnerabilities from this detector
            for vulnerability in getattr(detector_result, "vulnerabilities", []):
                severity = getattr(vulnerability, "severity", "low")
                # Convert Severity enum to string if needed
                if hasattr(severity, "value"):
                    severity = severity.value
                severity = severity.lower()

                # Count severities
                if severity in severity_counts:
                    severity_counts[severity] += 1

                # Group by detector
                if detector_name not in detector_map:
                    detector_map[detector_name] = {
                        "name": detector_name,
                        "icon": self._get_detector_icon(detector_name),
                        "vulnerabilities": [],
                    }

                # Convert vulnerability to dict for template
                vuln_dict = {
                    "title": getattr(
                        vulnerability,
                        "title",
                        getattr(vulnerability, "type", "Unknown Vulnerability"),
                    ),
                    "severity": severity,
                    "description": getattr(vulnerability, "description", ""),
                    "location": getattr(vulnerability, "location", ""),
                    "evidence": getattr(vulnerability, "evidence", ""),
                    "remediation": getattr(vulnerability, "remediation", ""),
                }
                detector_map[detector_name]["vulnerabilities"].append(vuln_dict)
                vulnerabilities.append(vuln_dict)

        # Convert to list for template
        detectors = list(detector_map.values())

        # Calculate risk score and level
        risk_score = getattr(scan_result, "risk_score", 0.0)
        risk_level = self._calculate_risk_level(risk_score)

        # Get scan configuration
        scan_config = getattr(scan_result, "scan_config", None)

        return {
            "target_url": getattr(scan_result, "target_url", "Unknown"),
            "scan_date": getattr(scan_result, "timestamp", datetime.now()).strftime(
                "%Y-%m-%d %H:%M"
            ),
            "risk_score": f"{risk_score:.1f}",
            "risk_level": risk_level,
            "total_vulnerabilities": len(vulnerabilities),
            "scan_duration": self._format_duration(
                getattr(scan_result, "scan_duration", 0)
            ),
            "severity_counts": severity_counts,
            "detectors": detectors,
            "scan_config": {
                "timeout": self._get_config_value(scan_config, "timeout", "30s"),
                "follow_redirects": self._get_config_value(
                    scan_config, "follow_redirects", "Yes"
                ),
                "ssl_verification": self._get_config_value(
                    scan_config, "verify_ssl", "Enabled"
                ),
            },
            "generation_timestamp": datetime.now().strftime("%Y-%m-%d at %H:%M:%S"),
        }

    def _calculate_risk_level(self, risk_score: float) -> str:
        """Calculate risk level based on risk score."""
        if risk_score >= 8.0:
            return "Critical"
        elif risk_score >= 6.0:
            return "High"
        elif risk_score >= 4.0:
            return "Medium"
        elif risk_score >= 2.0:
            return "Low"
        else:
            return "Very Low"

    def _format_duration(self, duration_seconds: float) -> str:
        """Format duration in seconds to human-readable string."""
        if duration_seconds < 1:
            return f"{duration_seconds * 1000:.0f}ms"
        elif duration_seconds < 60:
            return f"{duration_seconds:.2f}s"
        else:
            minutes = int(duration_seconds // 60)
            seconds = duration_seconds % 60
            return f"{minutes}m {seconds:.2f}s"

    def _get_config_value(self, scan_config, key: str, default: str) -> str:
        """Safely get configuration value with proper formatting."""
        if scan_config is None:
            return default

        # Try to get attribute from ScanConfig object
        value = getattr(scan_config, key, default)

        # Convert boolean values to Yes/No
        if isinstance(value, bool):
            return "Yes" if value else "No"

        # Format timeout with 's'
        if key == "timeout" and isinstance(value, (int, float)):
            return f"{value}s"

        return str(value)

    def _get_detector_icon(self, detector_name: str) -> str:
        """Get appropriate icon for detector type."""
        icon_map = {
            "Security Headers": "🛡️",
            "SQL Injection": "💉",
            "XSS": "🎯",
            "CORS": "🌐",
            "JWT": "🔑",
            "CSRF": "🔄",
            "XXE": "📄",
            "SSRF": "🔄",
            "File Inclusion": "📁",
            "Command Injection": "💻",
            "IDOR": "👤",
        }
        return icon_map.get(detector_name, "🔍")

    def generate_sample_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate a sample report for testing and demonstration.
        """
        from security_scanner.core.models import (
            ScanResult,
            DetectorResult,
            Vulnerability,
            ScanConfig,
        )
        from datetime import datetime

        # Create sample vulnerabilities
        sample_vulnerabilities = [
            Vulnerability(
                type="missing_security_headers",
                title="Missing Content-Security-Policy Header",
                severity="high",  # This should be a Severity enum in your actual model
                description="Content Security Policy header is missing, leaving the application vulnerable to XSS attacks",
                location="HTTP Response Headers",
                evidence="Response headers: X-Frame-Options: SAMEORIGIN\nStrict-Transport-Security: max-age=31536000\nMissing: Content-Security-Policy",
                remediation="Implement a Content Security Policy header with appropriate directives for your application",
            ),
            Vulnerability(
                type="missing_security_headers",
                title="Missing X-Content-Type-Options Header",
                severity="medium",
                description="X-Content-Type-Options header is missing, which could allow MIME type sniffing",
                location="HTTP Response Headers",
                evidence="Response does not include X-Content-Type-Options header",
                remediation="Add X-Content-Type-Options: nosniff header",
            ),
        ]

        # Create detector results
        detector_results = [
            DetectorResult(
                detector_name="Security Headers", vulnerabilities=sample_vulnerabilities
            )
        ]

        # Create sample scan result
        sample_result = ScanResult(
            target_url="https://www.example.com",
            timestamp=datetime.now(),
            detector_results=detector_results,
            scan_config=ScanConfig(
                target_url="https://www.example.com",
                timeout=30,
                verify_ssl=True,
                follow_redirects=True,
            ),
            scan_duration=12.45,
            risk_score=6.1,
            total_vulnerabilities=len(sample_vulnerabilities),
        )

        return self.generate(sample_result, output_path)
