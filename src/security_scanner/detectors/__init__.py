"""
Security Detectors Package

This package contains all vulnerability detectors for the security scanner.
"""

from .base import BaseDetector

# Import existing detectors
from .headers import HeadersDetector
from .cors import CORSDetector
from .jwt import JWTDetector

# Import new detectors
from .sql_injection import SQLInjectionDetector
from .xss import XSSDetector

# Export all detectors
__all__ = [
    # Base
    "BaseDetector",
    # Detectors
    "HeadersDetector",
    "CORSDetector",
    "JWTDetector",
    "SQLInjectionDetector",
    "XSSDetector",
]

# Available detector types
DETECTOR_CLASSES = {
    "headers": HeadersDetector,
    "cors": CORSDetector,
    "jwt": JWTDetector,
    "sql_injection": SQLInjectionDetector,
    "xss": XSSDetector,
}


def create_detector(detector_type: str):
    """Factory function to create detectors by type."""
    detector_class = DETECTOR_CLASSES.get(detector_type)
    if detector_class:
        return detector_class()
    raise ValueError(f"Unknown detector type: {detector_type}")
