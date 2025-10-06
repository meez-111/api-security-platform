from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from security_scanner.core.models import ScanResult


class BaseReporter(ABC):
    """
    Abstract base class for all report generators.
    """

    def __init__(self):
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)

    @abstractmethod
    def generate(
        self, scan_result: ScanResult, output_path: Optional[str] = None
    ) -> str:
        """
        Generate a report from scan results.

        Args:
            scan_result: The scan results to report on
            output_path: Optional custom output path

        Returns:
            Path to the generated report file
        """
        pass

    def _get_output_path(self, scan_result: ScanResult, extension: str) -> str:
        """
        Generate a default output path based on scan target and timestamp.
        """
        # Create filename from target URL and timestamp
        target_name = scan_result.target_url.replace("https://", "").replace(
            "http://", ""
        )
        target_name = "".join(c if c.isalnum() else "_" for c in target_name)
        timestamp = scan_result.timestamp.strftime("%Y%m%d_%H%M%S")

        filename = f"security_scan_{target_name}_{timestamp}.{extension}"
        return str(self.output_dir / filename)
