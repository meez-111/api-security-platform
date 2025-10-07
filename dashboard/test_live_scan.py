import os
import django
import asyncio
import sys

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "horsesec_dashboard.settings")
django.setup()

from scanner.models import ScanResult
from scanner.tasks import run_security_scan


async def test_live_scan():
    """Test the security scanner with a live target."""
    print("🧪 Testing live security scan...")

    # Create a test scan record
    scan_result = ScanResult.objects.create(
        target_url="https://httpbin.org/json", status="queued"  # A test API
    )

    print(f"🔍 Starting scan for: {scan_result.target_url}")

    try:
        await run_security_scan(scan_result.id)

        # Refresh from database
        scan_result.refresh_from_db()

        print(f"✅ Scan completed with status: {scan_result.status}")
        print(f"🎯 Risk score: {scan_result.risk_score}")
        print(f"⏱️ Duration: {scan_result.scan_duration}s")
        print(f"📊 Vulnerabilities found: {scan_result.total_vulnerabilities}")

        # Show vulnerabilities
        vulnerabilities = scan_result.vulnerability_set.all()
        for vuln in vulnerabilities:
            print(
                f"   ⚠️ {vuln.detector_name} - {vuln.vulnerability_type} ({vuln.severity})"
            )

    except Exception as e:
        print(f"❌ Scan failed: {e}")


if __name__ == "__main__":
    asyncio.run(test_live_scan())
