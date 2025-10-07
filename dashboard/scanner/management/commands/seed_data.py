from django.core.management.base import BaseCommand
from scanner.models import ScanProfile
from django.utils import timezone


class Command(BaseCommand):
    help = "Seed the database with initial scan profiles and sample data"

    def handle(self, *args, **options):
        self.stdout.write("🌱 Seeding database with initial data...")

        # Create default scan profiles
        scan_profiles = [
            {
                "name": "Quick Scan",
                "description": "Fast scan with basic security checks - perfect for development environments",
                "config": {
                    "timeout": 15,
                    "follow_redirects": True,
                    "verify_ssl": True,
                    "scan_jwt": False,
                    "scan_headers": True,
                    "scan_cors": True,
                    "scan_sql_injection": False,
                    "scan_xss": False,
                    "headers": {
                        "User-Agent": "HorseSec-Scanner/1.0.0",
                        "Accept": "application/json",
                    },
                },
                "is_default": True,
            },
            {
                "name": "Full Security Scan",
                "description": "Comprehensive security scan with all detectors - for production readiness",
                "config": {
                    "timeout": 60,
                    "follow_redirects": True,
                    "verify_ssl": True,
                    "scan_jwt": True,
                    "scan_headers": True,
                    "scan_cors": True,
                    "scan_sql_injection": True,
                    "scan_xss": True,
                    "headers": {
                        "User-Agent": "HorseSec-Scanner/1.0.0",
                        "Accept": "application/json",
                        "Authorization": "Bearer {{token}}",
                    },
                },
                "is_default": False,
            },
            {
                "name": "API Security Scan",
                "description": "Focused scan for API-specific security issues",
                "config": {
                    "timeout": 45,
                    "follow_redirects": True,
                    "verify_ssl": True,
                    "scan_jwt": True,
                    "scan_headers": True,
                    "scan_cors": True,
                    "scan_sql_injection": True,
                    "scan_xss": False,
                    "headers": {
                        "User-Agent": "HorseSec-Scanner/1.0.0",
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                },
                "is_default": False,
            },
            {
                "name": "Compliance Scan",
                "description": "Scan focused on security headers and CORS for compliance requirements",
                "config": {
                    "timeout": 30,
                    "follow_redirects": True,
                    "verify_ssl": True,
                    "scan_jwt": False,
                    "scan_headers": True,
                    "scan_cors": True,
                    "scan_sql_injection": False,
                    "scan_xss": False,
                    "headers": {
                        "User-Agent": "HorseSec-Scanner/1.0.0",
                        "Accept": "application/json",
                    },
                },
                "is_default": False,
            },
        ]

        created_count = 0
        updated_count = 0

        for profile_data in scan_profiles:
            profile, created = ScanProfile.objects.update_or_create(
                name=profile_data["name"],
                defaults={
                    "description": profile_data["description"],
                    "config": profile_data["config"],
                    "is_default": profile_data["is_default"],
                },
            )

            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Created scan profile: {profile.name}")
                )
            else:
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f"📝 Updated scan profile: {profile.name}")
                )

        # Ensure only one default profile
        default_profiles = ScanProfile.objects.filter(is_default=True)
        if default_profiles.count() > 1:
            # Keep the first one as default, unset others
            first_default = default_profiles.first()
            for profile in default_profiles.exclude(id=first_default.id):
                profile.is_default = False
                profile.save()
                self.stdout.write(
                    self.style.WARNING(
                        f"🔧 Fixed multiple defaults: {profile.name} is no longer default"
                    )
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"🎉 Successfully seeded database! "
                f"Created: {created_count}, Updated: {updated_count}, "
                f"Total profiles: {ScanProfile.objects.count()}"
            )
        )

        # Display the created profiles
        self.stdout.write("\n📋 Available Scan Profiles:")
        for profile in ScanProfile.objects.all():
            status = " (Default)" if profile.is_default else ""
            self.stdout.write(f"   • {profile.name}{status}")
            self.stdout.write(f"     {profile.description}")
            self.stdout.write(f"     Config: {len(profile.config)} settings")
            self.stdout.write("")
