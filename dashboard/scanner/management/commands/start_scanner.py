from django.core.management.base import BaseCommand
from django.utils import timezone
import time
import asyncio
import sys
import os

# Add the security_scanner to Python path
project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
src_path = os.path.join(project_root, "../../../src")
sys.path.insert(0, src_path)


class Command(BaseCommand):
    help = "Start the security scanner worker (alternative to Celery)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--interval",
            type=int,
            default=5,
            help="Polling interval in seconds for checking new scans",
        )

    def handle(self, *args, **options):
        interval = options["interval"]

        self.stdout.write(
            self.style.SUCCESS(
                f"🚀 Starting security scanner worker (interval: {interval}s)"
            )
        )

        try:
            from scanner.models import ScanResult
            from scanner.tasks import run_security_scan

            while True:
                # Check for queued scans
                queued_scans = ScanResult.objects.filter(status="queued")

                if queued_scans.exists():
                    self.stdout.write(f"📋 Found {queued_scans.count()} queued scans")

                    for scan in queued_scans:
                        self.stdout.write(f"🔄 Starting scan: {scan.target_url}")
                        try:
                            # Run the scan
                            asyncio.run(run_security_scan(scan))
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f"✅ Completed scan: {scan.target_url}"
                                )
                            )
                        except Exception as e:
                            self.stdout.write(
                                self.style.ERROR(
                                    f"❌ Failed scan {scan.target_url}: {str(e)}"
                                )
                            )

                time.sleep(interval)

        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("👋 Scanner worker stopped"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"💥 Worker error: {str(e)}"))
