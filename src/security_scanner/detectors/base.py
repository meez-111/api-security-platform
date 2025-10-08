from abc import ABC, abstractmethod
from typing import List, Optional
import uuid

from security_scanner.core.models import (
    DetectorResult,
    ScanConfig,
    Vulnerability,
    Severity,
)


class BaseDetector(ABC):
    """
    Abstract base class for all vulnerability detectors.

    All detectors (JWT, Headers, CORS, etc.) must inherit from this class
    and implement the scan method.
    """

    def __init__(self):
        self.name = self.__class__.__name__
        self.description = "Base vulnerability detector"
        self.supported_types: List[str] = []

    @abstractmethod
    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Main scanning method that all detectors must implement.

        Args:
            target_url: The URL to scan for vulnerabilities
            config: Scan configuration settings

        Returns:
            DetectorResult: Contains found vulnerabilities or errors
        """

    def get_name(self) -> str:
        """Returns the detector name"""
        return self.name

    def get_description(self) -> str:
        """Returns what this detector checks for"""
        return self.description

    def get_supported_types(self) -> List[str]:
        """Returns the vulnerability types this detector can find"""
        return self.supported_types

    def create_vulnerability(
        self,
        vuln_type: str,
        title: str,
        description: str,
        severity: Severity,
        evidence: str,
        remediation: str,
        location: Optional[str] = None,
        cvss_score: Optional[float] = None,
    ) -> Vulnerability:
        """
        Helper method to create standardized vulnerability objects.
        """
        return Vulnerability(
            id=str(uuid.uuid4()),  # Generate unique ID
            type=vuln_type,
            title=title,
            description=description,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            location=location,
            cvss_score=cvss_score,
        )

    def create_detector_result(
        self, vulnerabilities: List[Vulnerability] = None, error: Optional[str] = None
    ) -> DetectorResult:
        """
        Helper method to create standardized detector results.

        Note: Removed scan_duration parameter to match your DetectorResult model
        """
        if vulnerabilities is None:
            vulnerabilities = []

        return DetectorResult(
            detector_name=self.name, vulnerabilities=vulnerabilities, error=error
        )
