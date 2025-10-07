from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from .models import ScanResult, ScanProfile, Vulnerability
from .tasks import run_security_scan_task
import asyncio
import sys
import os

# Add the security_scanner to Python path - FIXED PATH
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
src_path = os.path.join(project_root, "src")
sys.path.insert(0, src_path)

print(f"Looking for security_scanner in: {src_path}")

# Import security scanner with error handling
try:
    from security_scanner.core.models import ScanConfig as ScannerConfig
    from security_scanner.core.scanner import create_security_scanner

    SECURITY_SCANNER_AVAILABLE = True
    print("✅ Security scanner imported successfully!")
except ImportError as e:
    print(f"❌ Could not import security_scanner: {e}")
    SECURITY_SCANNER_AVAILABLE = False

    # Create dummy classes for development
    class ScannerConfig:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    def create_security_scanner(config):
        class DummyScanner:
            async def scan(self):
                class DummyResult:
                    def __init__(self):
                        self.risk_score = 0.0
                        self.scan_duration = 0.0
                        self.detector_results = []

                    def dict(self):
                        return {
                            "risk_score": self.risk_score,
                            "scan_duration": self.scan_duration,
                            "detector_results": self.detector_results,
                        }

                return DummyResult()

        return DummyScanner()


@login_required
def dashboard(request):
    """Main dashboard view."""
    # Get recent scans
    recent_scans = ScanResult.objects.filter(user=request.user)[:5]

    # Get scan statistics
    total_scans = ScanResult.objects.filter(user=request.user).count()
    completed_scans = ScanResult.objects.filter(
        user=request.user, status="completed"
    ).count()

    # Calculate total vulnerabilities from completed scans
    completed_scan_results = ScanResult.objects.filter(
        user=request.user, status="completed"
    )
    total_vulnerabilities = sum(
        scan.total_vulnerabilities for scan in completed_scan_results
    )

    # Calculate vulnerability counts by severity
    critical_count = sum(scan.critical_count for scan in completed_scan_results)
    high_count = sum(scan.high_count for scan in completed_scan_results)
    medium_count = sum(scan.medium_count for scan in completed_scan_results)
    low_count = sum(scan.low_count for scan in completed_scan_results)

    context = {
        "recent_scans": recent_scans,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "total_vulnerabilities": total_vulnerabilities,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "scanner_available": SECURITY_SCANNER_AVAILABLE,
    }

    return render(request, "scanner/dashboard.html", context)


@login_required
def new_scan(request):
    """Create a new security scan."""
    scan_profiles = ScanProfile.objects.all()

    if not SECURITY_SCANNER_AVAILABLE:
        messages.error(
            request, "Security scanner is not available. Please check the installation."
        )
        return render(
            request, "scanner/new_scan.html", {"scan_profiles": scan_profiles}
        )

    if request.method == "POST":
        target_url = request.POST.get("target_url")
        profile_id = request.POST.get("scan_profile")

        if not target_url:
            messages.error(request, "Target URL is required.")
            return render(
                request, "scanner/new_scan.html", {"scan_profiles": scan_profiles}
            )

        try:
            # Get or create scan profile
            if profile_id:
                scan_profile = ScanProfile.objects.get(id=profile_id)
                config_data = scan_profile.config
            else:
                scan_profile = None
                default_profile = ScanProfile.objects.filter(is_default=True).first()
                if default_profile:
                    config_data = default_profile.config
                else:
                    # Fallback configuration
                    config_data = {
                        "timeout": 30,
                        "scan_jwt": True,
                        "scan_headers": True,
                        "scan_cors": True,
                        "scan_sql_injection": True,
                        "scan_xss": True,
                    }

            # Create scan configuration
            scanner_config = ScannerConfig(
                target_url=target_url,
                timeout=config_data.get("timeout", 30),
                scan_jwt=config_data.get("scan_jwt", True),
                scan_headers=config_data.get("scan_headers", True),
                scan_cors=config_data.get("scan_cors", True),
                scan_sql_injection=config_data.get("scan_sql_injection", True),
                scan_xss=config_data.get("scan_xss", True),
            )

            # Create scan result in database
            scan_result = ScanResult.objects.create(
                target_url=target_url,
                scan_profile=scan_profile,
                user=request.user,
                status="queued",
                scan_config=config_data,
            )

            # Start the scan asynchronously with Celery
            run_security_scan_task.delay(scan_result.id)

            messages.success(request, f"Scan started for {target_url}")
            return redirect("scan_detail", pk=scan_result.pk)

        except Exception as e:
            messages.error(request, f"Error starting scan: {str(e)}")

    return render(request, "scanner/new_scan.html", {"scan_profiles": scan_profiles})


async def run_security_scan(scan_result, scanner_config):
    """Run security scan asynchronously and save results."""
    try:
        # Update status to running
        scan_result.status = "running"
        scan_result.started_at = timezone.now()
        scan_result.save()

        # Run the scan
        scanner = create_security_scanner(scanner_config)
        result = await scanner.scan()

        # Save results
        scan_result.status = "completed"
        scan_result.completed_at = timezone.now()
        scan_result.risk_score = result.risk_score
        scan_result.scan_duration = result.scan_duration
        scan_result.raw_results = result.dict()

        # Update vulnerability counts
        scan_result.update_vulnerability_counts()

        # Create vulnerability records
        for detector_result in result.detector_results:
            for vulnerability in detector_result.vulnerabilities:
                Vulnerability.objects.create(
                    scan_result=scan_result,
                    detector_name=detector_result.detector_name,
                    vulnerability_type=vulnerability.type,
                    severity=vulnerability.severity.value,
                    description=vulnerability.description,
                    evidence=vulnerability.evidence,
                    remediation=vulnerability.remediation,
                )

        scan_result.save()

    except Exception as e:
        scan_result.status = "failed"
        scan_result.error_message = str(e)
        scan_result.completed_at = timezone.now()
        scan_result.save()


@login_required
def scan_detail(request, pk):
    """View scan details."""
    scan = get_object_or_404(ScanResult, pk=pk, user=request.user)

    # Get vulnerabilities for this scan
    vulnerabilities = scan.vulnerabilities.all()

    context = {
        "scan": scan,
        "vulnerabilities": vulnerabilities,
    }

    return render(request, "scanner/scan_detail.html", context)


@login_required
def scan_list(request):
    """List all scans for the user."""
    scans = ScanResult.objects.filter(user=request.user).order_by("-created_at")

    context = {
        "scans": scans,
    }

    return render(request, "scanner/scan_list.html", context)


@login_required
def scan_results(request, pk):
    """View detailed scan results."""
    scan = get_object_or_404(ScanResult, pk=pk, user=request.user)

    context = {
        "scan": scan,
    }

    return render(request, "scanner/scan_results.html", context)


@login_required
def scan_delete(request, pk):
    """Delete a scan."""
    scan = get_object_or_404(ScanResult, pk=pk, user=request.user)

    if request.method == "POST":
        scan.delete()
        messages.success(request, "Scan deleted successfully.")
        return redirect("scanner:scan_list")

    context = {
        "scan": scan,
    }

    return render(request, "scanner/scan_confirm_delete.html", context)


@login_required
def scan_status_api(request, pk):
    """API endpoint to get scan status."""
    scan = get_object_or_404(ScanResult, pk=pk, user=request.user)

    return JsonResponse(
        {
            "status": scan.status,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "risk_score": scan.risk_score,
            "scan_duration": scan.scan_duration,
        }
    )


@login_required
def profile_list(request):
    """List all scan profiles."""
    profiles = ScanProfile.objects.all()

    context = {
        "profiles": profiles,
    }

    return render(request, "scanner/profile_list.html", context)


@login_required
def scan_progress_api(request, pk):
    """API endpoint to get scan progress."""
    scan = get_object_or_404(ScanResult, pk=pk, user=request.user)

    # Calculate progress based on status
    if scan.status == "completed":
        progress = 100
    elif scan.status == "running":
        # Simulate progress - in a real app, this would come from the scanner
        if scan.started_at:
            elapsed = timezone.now() - scan.started_at
            # Assume average scan takes 60 seconds
            progress = min(90, int((elapsed.total_seconds() / 60) * 100))
        else:
            progress = 10
    elif scan.status == "failed":
        progress = 100
    else:  # queued
        progress = 5

    return JsonResponse(
        {
            "status": scan.status,
            "progress": progress,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "risk_score": scan.risk_score,
            "scan_duration": scan.scan_duration,
        }
    )
