from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class Severity(Enum):
    """Severity levels for vulnerabilities."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Vulnerability(BaseModel):
    """Represents a security vulnerability finding."""

    type: str = Field(..., description="Type of vulnerability")
    severity: Severity = Field(..., description="Severity level")
    description: str = Field(..., description="Detailed description")
    evidence: str = Field(..., description="Evidence or proof of concept")
    remediation: str = Field(..., description="Remediation advice")


class DetectorResult(BaseModel):
    """Results from a single security detector."""

    detector_name: str = Field(..., description="Name of the detector")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Found vulnerabilities"
    )
    error: Optional[str] = Field(None, description="Error message if detector failed")


class ScanConfig(BaseModel):
    """Configuration for security scans."""

    target_url: str = Field(..., description="Target API URL to scan")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    headers: Optional[Dict[str, str]] = Field(
        default=None, description="Custom headers"
    )
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")

    # Detector flags
    scan_jwt: bool = Field(default=True, description="Enable JWT scanning")
    scan_headers: bool = Field(
        default=True, description="Enable security headers scanning"
    )
    scan_cors: bool = Field(
        default=True, description="Enable CORS misconfiguration scanning"
    )
    scan_sql_injection: bool = Field(
        default=True, description="Enable SQL injection scanning"
    )
    scan_xss: bool = Field(default=True, description="Enable XSS scanning")

    # Updated for Pydantic v2
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "target_url": "https://api.example.com",
                "timeout": 30,
                "follow_redirects": True,
                "verify_ssl": True,
                "scan_jwt": True,
                "scan_headers": True,
                "scan_cors": True,
                "scan_sql_injection": True,
                "scan_xss": True,
            }
        }
    )


class ScanResult(BaseModel):
    """Results from a complete security scan."""

    target_url: str = Field(..., description="Scanned target URL")
    scan_config: ScanConfig = Field(..., description="Configuration used for scan")
    detector_results: List[DetectorResult] = Field(
        ..., description="Results from all detectors"
    )
    total_vulnerabilities: int = Field(
        ..., description="Total number of vulnerabilities found"
    )
    risk_score: float = Field(..., description="Overall risk score (0-10)")
    scan_duration: float = Field(..., description="Scan duration in seconds")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="When the scan was completed"
    )

    def get_vulnerabilities_by_severity(
        self, severity: Severity
    ) -> List[Vulnerability]:
        """Get all vulnerabilities of a specific severity level."""
        vulnerabilities = []
        for detector_result in self.detector_results:
            for vulnerability in detector_result.vulnerabilities:
                if vulnerability.severity == severity:
                    vulnerabilities.append(vulnerability)
        return vulnerabilities

    def dict(self, *args, **kwargs):
        """Override dict method to handle serialization properly."""
        data = super().model_dump(*args, **kwargs)
        # Convert datetime to ISO format string
        if "timestamp" in data and isinstance(data["timestamp"], datetime):
            data["timestamp"] = data["timestamp"].isoformat()
        return data
