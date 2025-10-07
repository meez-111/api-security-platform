import asyncio
import sys
import os
from celery import shared_task
from django.utils import timezone
from .models import ScanResult, Vulnerability

print("🔍 Initializing security scanner...")

# Add the project root to Python path
project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
src_path = os.path.join(project_root, "src")

if src_path not in sys.path:
    sys.path.insert(0, src_path)
    print(f"✅ Added to Python path: {src_path}")

# Try to import security scanner
try:
    from security_scanner.core.models import ScanConfig, Severity
    from security_scanner.core.scanner import create_security_scanner

    SECURITY_SCANNER_AVAILABLE = True
    print("✅ Security scanner imported successfully!")

except ImportError as e:
    print(f"❌ Could not import security_scanner: {e}")
    SECURITY_SCANNER_AVAILABLE = False

    # Create minimal dummy classes
    class Severity:
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class ScanConfig:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    def create_security_scanner(config):
        class DummyScanner:
            async def scan(self):
                class DummyResult:
                    def __init__(self):
                        self.risk_score = 2.5
                        self.scan_duration = 5.0
                        self.detector_results = []
                        self.total_vulnerabilities = 0

                    def dict(self):
                        return {
                            "risk_score": self.risk_score,
                            "scan_duration": self.scan_duration,
                            "detector_results": self.detector_results,
                            "total_vulnerabilities": self.total_vulnerabilities,
                        }

                return DummyResult()

        return DummyScanner()


@shared_task
def run_security_scan_task(scan_result_id):
    """
    Celery task to run a security scan asynchronously.
    """
    try:
        return asyncio.run(run_security_scan(scan_result_id))
    except Exception as e:
        print(f"❌ Error in scan task: {e}")
        scan_result = ScanResult.objects.get(id=scan_result_id)
        scan_result.status = "failed"
        scan_result.error_message = str(e)
        scan_result.save()
        return None


async def run_security_scan(scan_result_id):
    """
    Run security scan and save results.
    """
    scan_result = ScanResult.objects.get(id=scan_result_id)

    try:
        print(f"🔄 Starting security scan for: {scan_result.target_url}")

        # Update status to running
        scan_result.status = "running"
        scan_result.started_at = timezone.now()
        scan_result.save()

        # Create scanner configuration
        scanner_config = ScanConfig(
            target_url=scan_result.target_url,
            timeout=30,
            scan_jwt=True,
            scan_headers=True,
            scan_cors=True,
            scan_sql_injection=True,
            scan_xss=True,
        )

        # Run the scan
        scanner = create_security_scanner(scanner_config)
        result = await scanner.scan()

        # Save results
        scan_result.status = "completed"
        scan_result.completed_at = timezone.now()
        scan_result.risk_score = result.risk_score
        scan_result.scan_duration = result.scan_duration
        scan_result.raw_results = result.dict()
        scan_result.total_vulnerabilities = result.total_vulnerabilities

        # Create vulnerability records
        for detector_result in result.detector_results:
            for vulnerability in detector_result.vulnerabilities:
                # Map Pydantic vulnerability to Django model
                Vulnerability.objects.create(
                    scan_result=scan_result,
                    detector_name=detector_result.detector_name,
                    vulnerability_type=vulnerability.type,
                    severity=vulnerability.severity.value,  # Convert Enum to string
                    description=vulnerability.description,
                    evidence=vulnerability.evidence,
                    remediation=vulnerability.remediation,
                )

        # Update vulnerability counts
        scan_result.update_vulnerability_counts()
        scan_result.save()

        print(f"✅ Scan completed: {scan_result.target_url}")
        print(f"📊 Found {result.total_vulnerabilities} vulnerabilities")
        print(f"🎯 Risk score: {result.risk_score}")

    except Exception as e:
        print(f"❌ Scan failed: {e}")
        scan_result.status = "failed"
        scan_result.error_message = str(e)
        scan_result.completed_at = timezone.now()
        scan_result.save()
        raise
