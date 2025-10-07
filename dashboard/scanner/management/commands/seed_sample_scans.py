from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from scanner.models import ScanProfile, ScanResult, Vulnerability
from django.utils import timezone
from datetime import timedelta
import random


class Command(BaseCommand):
    help = "Create sample scan results for testing and demonstration"

    def handle(self, *args, **options):
        self.stdout.write("🎨 Creating sample scan data...")

        # Get or create a demo user
        user, created = User.objects.get_or_create(
            username="demo",
            defaults={
                "email": "demo@horsesec.com",
                "is_staff": False,
                "is_superuser": False,
            },
        )
        if created:
            user.set_password("demo123")
            user.save()
            self.stdout.write(self.style.SUCCESS("✅ Created demo user"))

        # Get scan profiles
        try:
            quick_profile = ScanProfile.objects.get(name="Quick Scan")
            full_profile = ScanProfile.objects.get(name="Full Security Scan")
        except ScanProfile.DoesNotExist:
            self.stdout.write(
                self.style.ERROR("❌ Scan profiles not found. Run seed_data first.")
            )
            return

        # Sample vulnerabilities data
        sample_vulnerabilities = [
            {
                "type": "Missing Security Header: X-Content-Type-Options",
                "severity": "medium",
                "description": "The X-Content-Type-Options header is missing, which could allow MIME type sniffing attacks.",
                "evidence": "Response headers do not include X-Content-Type-Options",
                "remediation": 'Add "X-Content-Type-Options: nosniff" to all HTTP responses.',
            },
            {
                "type": "CORS Misconfiguration: Wildcard Origin",
                "severity": "high",
                "description": "CORS is configured to allow any origin (*) which poses a security risk.",
                "evidence": 'Access-Control-Allow-Origin header is set to "*"',
                "remediation": "Restrict Access-Control-Allow-Origin to specific trusted origins instead of using wildcard.",
            },
            {
                "type": "Missing Security Header: X-Frame-Options",
                "severity": "medium",
                "description": "The X-Frame-Options header is missing, which could allow clickjacking attacks.",
                "evidence": "Response headers do not include X-Frame-Options",
                "remediation": 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" to all HTTP responses.',
            },
            {
                "type": "SQL Injection Potential",
                "severity": "high",
                "description": "Endpoint accepts parameters that could be vulnerable to SQL injection attacks.",
                "evidence": "User input is reflected in error messages without proper sanitization",
                "remediation": "Use parameterized queries or prepared statements. Validate and sanitize all user inputs.",
            },
            {
                "type": "JWT Token Exposure",
                "severity": "medium",
                "description": "Potential JWT token endpoint found that may expose sensitive authentication data.",
                "evidence": "Endpoint /api/auth/token returns JWT tokens in response",
                "remediation": "Ensure JWT tokens are properly secured, use short expiration times, and implement token revocation.",
            },
        ]

        # Sample scan results
        sample_scans = [
            {
                "target_url": "https://api.example.com/v1/users",
                "profile": quick_profile,
                "status": "completed",
                "risk_score": 3.2,
                "duration": 12.5,
                "vulnerabilities": [0, 1],  # indices from sample_vulnerabilities
            },
            {
                "target_url": "https://staging-api.company.com/graphql",
                "profile": full_profile,
                "status": "completed",
                "risk_score": 7.8,
                "duration": 45.2,
                "vulnerabilities": [0, 1, 2, 3],
            },
            {
                "target_url": "https://auth.service.com/oauth2",
                "profile": full_profile,
                "status": "completed",
                "risk_score": 5.1,
                "duration": 38.7,
                "vulnerabilities": [4, 0],
            },
            {
                "target_url": "https://api.test-app.io/data",
                "profile": quick_profile,
                "status": "running",
                "risk_score": 0.0,
                "duration": 8.3,
                "vulnerabilities": [],
            },
            {
                "target_url": "https://broken-api.site.com/endpoint",
                "profile": full_profile,
                "status": "failed",
                "risk_score": 0.0,
                "duration": 5.1,
                "vulnerabilities": [],
                "error_message": "Connection timeout after 30 seconds",
            },
        ]

        created_count = 0

        for i, scan_data in enumerate(sample_scans):
            # Create scan with timestamp offset
            created_at = timezone.now() - timedelta(
                days=len(sample_scans) - i, hours=random.randint(1, 12)
            )

            scan = ScanResult.objects.create(
                target_url=scan_data["target_url"],
                scan_profile=scan_data["profile"],
                user=user,
                status=scan_data["status"],
                scan_config=scan_data["profile"].config,
                total_vulnerabilities=len(scan_data["vulnerabilities"]),
                risk_score=scan_data["risk_score"],
                scan_duration=scan_data["duration"],
                created_at=created_at,
            )

            # Set started and completed times for completed/failed scans
            if scan_data["status"] in ["completed", "failed"]:
                scan.started_at = created_at
                scan.completed_at = created_at + timedelta(
                    seconds=scan_data["duration"]
                )
                scan.save()

            # Add error message for failed scans
            if scan_data["status"] == "failed":
                scan.error_message = scan_data["error_message"]
                scan.save()

            # Create vulnerability records
            for vuln_index in scan_data["vulnerabilities"]:
                vuln_data = sample_vulnerabilities[vuln_index]
                Vulnerability.objects.create(
                    scan_result=scan,
                    detector_name=(
                        "Security Headers"
                        if "Header" in vuln_data["type"]
                        else (
                            "CORS Detector"
                            if "CORS" in vuln_data["type"]
                            else (
                                "SQL Injection"
                                if "SQL" in vuln_data["type"]
                                else (
                                    "JWT Detector"
                                    if "JWT" in vuln_data["type"]
                                    else "General"
                                )
                            )
                        )
                    ),
                    vulnerability_type=vuln_data["type"],
                    severity=vuln_data["severity"],
                    description=vuln_data["description"],
                    evidence=vuln_data["evidence"],
                    remediation=vuln_data["remediation"],
                )

            # Update vulnerability counts
            if scan_data["status"] == "completed":
                scan.update_vulnerability_counts()

            created_count += 1
            self.stdout.write(
                self.style.SUCCESS(f"✅ Created sample scan: {scan.target_url}")
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"🎉 Created {created_count} sample scans! "
                f"Total scans in database: {ScanResult.objects.count()}"
            )
        )

        # Display summary
        self.stdout.write("\n📊 Sample Data Summary:")
        self.stdout.write(f"   • Users: {User.objects.count()}")
        self.stdout.write(f"   • Scan Profiles: {ScanProfile.objects.count()}")
        self.stdout.write(f"   • Scan Results: {ScanResult.objects.count()}")
        self.stdout.write(f"   • Vulnerabilities: {Vulnerability.objects.count()}")

        self.stdout.write("\n👤 Demo User Credentials:")
        self.stdout.write("   Username: demo")
        self.stdout.write("   Password: demo123")
        self.stdout.write("\n🔗 You can now log in and explore the sample data!")
