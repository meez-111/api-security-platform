from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel


class Severity(str, Enum):
    """Vulnerability severity levels based on CVSS standards"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Vulnerability(BaseModel):
    """
    Represents a single security vulnerability found during scanning.

    Attributes:
        id: Unique identifier for tracking
        type: Vulnerability category (jwt, cors, headers, etc.)
        title: Short, descriptive title
        description: Detailed explanation of the issue
        severity: Risk level (Critical/High/Medium/Low)
        evidence: Proof that the vulnerability exists
        remediation: Step-by-step fix instructions
        location: Where the issue was found
        cvss_score: Standardized risk score (0-10)
    """

    id: str
    type: str
    title: str
    description: str
    severity: Severity
    evidence: str
    remediation: str
    location: Optional[str] = None
    cvss_score: Optional[float] = None


class DetectorResult(BaseModel):
    """
    Results from a single vulnerability detector.

    Attributes:
        detector_name: Name of the detector that ran
        vulnerabilities: List of found vulnerabilities
        scan_duration: How long the scan took in seconds
        error: Any errors encountered during scanning
    """

    detector_name: str
    vulnerabilities: List[Vulnerability] = []
    scan_duration: float = 0.0
    error: Optional[str] = None

    @property
    def passed(self) -> bool:
        """Returns True if no vulnerabilities were found"""
        return len(self.vulnerabilities) == 0 and self.error is None


class ScanConfig(BaseModel):
    """
    User configuration for security scans.

    Attributes:
        target_url: API endpoint to scan
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
        headers: Custom headers to include in requests
        verify_ssl: SSL certificate verification
        scan_jwt: Enable JWT vulnerability detector
        scan_headers: Enable security headers detector
        scan_cors: Enable CORS misconfiguration detector
    """

    target_url: str
    timeout: int = 30
    follow_redirects: bool = True
    headers: Dict[str, str] = {}
    verify_ssl: bool = True
    scan_jwt: bool = True
    scan_headers: bool = True
    scan_cors: bool = True


class ScanResult(BaseModel):
    """
    Complete results from a security scan.

    Attributes:
        target_url: Scanned API endpoint
        scan_config: Configuration used for the scan
        detector_results: Results from all detectors
        total_vulnerabilities: Count of all findings
        risk_score: Overall risk score (0-10)
        scan_duration: Total scan time in seconds
        timestamp: When the scan was run
    """

    target_url: str
    scan_config: ScanConfig
    detector_results: List[DetectorResult] = []
    total_vulnerabilities: int = 0
    risk_score: float = 0.0
    scan_duration: float = 0.0
    timestamp: datetime = datetime.now()

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on vulnerabilities"""
        # We'll implement this logic later
        return self.risk_score
