import json
from typing import Optional, Dict, Any
from pathlib import Path
from security_scanner.core.models import ScanResult
from security_scanner.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """
    Generates JSON security reports for integration with other tools.
    """

    def generate(
        self, scan_result: ScanResult, output_path: Optional[str] = None
    ) -> str:
        """Generate JSON security report."""
        if output_path is None:
            output_path = self._get_output_path(scan_result, "json")

        # Convert scan result to JSON-serializable format
        report_data = self._convert_to_dict(scan_result)

        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return output_path

    def _convert_to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to a JSON-serializable dictionary."""
        return {
            "metadata": {
                "scanner": "HorseSec API Security Scanner",
                "version": "1.0.0",
                "timestamp": scan_result.timestamp.isoformat(),
                "target_url": scan_result.target_url,
                "scan_duration": scan_result.scan_duration,
                "risk_score": scan_result.risk_score,
            },
            "summary": {
                "total_vulnerabilities": scan_result.total_vulnerabilities,
                "vulnerabilities_by_severity": self._count_by_severity(scan_result),
                "vulnerabilities_by_detector": self._count_by_detector(scan_result),
            },
            "scan_config": {
                "timeout": scan_result.scan_config.timeout,
                "follow_redirects": scan_result.scan_config.follow_redirects,
                "verify_ssl": scan_result.scan_config.verify_ssl,
            },
            "results": [
                {
                    "detector_name": result.detector_name,
                    "scan_duration": result.scan_duration,
                    "error": result.error,
                    "vulnerabilities": [
                        {
                            "id": vuln.id,
                            "type": vuln.type,
                            "title": vuln.title,
                            "description": vuln.description,
                            "severity": vuln.severity.value,
                            "evidence": vuln.evidence,
                            "remediation": vuln.remediation,
                            "location": vuln.location,
                            "cvss_score": vuln.cvss_score,
                        }
                        for vuln in result.vulnerabilities
                    ],
                }
                for result in scan_result.detector_results
            ],
        }

    def _count_by_severity(self, scan_result: ScanResult) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for result in scan_result.detector_results:
            for vuln in result.vulnerabilities:
                counts[vuln.severity.value] += 1

        return counts

    def _count_by_detector(self, scan_result: ScanResult) -> Dict[str, int]:
        """Count vulnerabilities by detector."""
        counts = {}

        for result in scan_result.detector_results:
            counts[result.detector_name] = len(result.vulnerabilities)

        return counts
