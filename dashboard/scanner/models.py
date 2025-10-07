from django.db import models
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
import json
from datetime import datetime


# Define choices at the top level so they're available to all models
SCAN_STATUS_CHOICES = [
    ("queued", "Queued"),
    ("running", "Running"),
    ("completed", "Completed"),
    ("failed", "Failed"),
    ("cancelled", "Cancelled"),
]

SEVERITY_CHOICES = [
    ("info", "Info"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]

FREQUENCY_CHOICES = [
    ("daily", "Daily"),
    ("weekly", "Weekly"),
    ("monthly", "Monthly"),
]


class ScanProfile(models.Model):
    """Predefined scan configurations."""

    name = models.CharField(max_length=100)
    description = models.TextField()
    config = models.JSONField(default=dict)  # Stores scan configuration as JSON
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ["name"]
        db_table = "scan_profiles"

    def get_absolute_url(self):
        return reverse("scan_profile_detail", kwargs={"pk": self.pk})


class ScanResult(models.Model):
    """Stores results of security scans."""

    # Basic scan information
    target_url = models.URLField(max_length=500)
    scan_profile = models.ForeignKey(
        ScanProfile, on_delete=models.SET_NULL, null=True, blank=True
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(
        max_length=20, choices=SCAN_STATUS_CHOICES, default="queued"
    )

    # Scan configuration (snapshot at time of scan)
    scan_config = models.JSONField(default=dict)

    # Results
    total_vulnerabilities = models.IntegerField(default=0)
    risk_score = models.FloatField(default=0.0)
    scan_duration = models.FloatField(default=0.0)  # in seconds

    # Vulnerability counts by severity
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)

    # Raw results data
    raw_results = models.JSONField(null=True, blank=True)  # Full scan results

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Error information
    error_message = models.TextField(blank=True)

    def __str__(self):
        return f"Scan of {self.target_url} - {self.status}"

    class Meta:
        ordering = ["-created_at"]
        db_table = "scan_results"
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["created_at"]),
            models.Index(fields=["user", "created_at"]),
        ]

    def get_absolute_url(self):
        return reverse("scan_result_detail", kwargs={"pk": self.pk})

    @property
    def is_completed(self):
        return self.status == "completed"

    @property
    def is_failed(self):
        return self.status == "failed"

    @property
    def is_running(self):
        return self.status == "running"

    @property
    def duration_formatted(self):
        """Return formatted duration."""
        if self.scan_duration < 60:
            return f"{self.scan_duration:.1f}s"
        else:
            minutes = int(self.scan_duration // 60)
            seconds = self.scan_duration % 60
            return f"{minutes}m {seconds:.1f}s"

    def update_vulnerability_counts(self):
        """Update vulnerability counts from raw results."""
        if not self.raw_results:
            return

        try:
            # Reset counts
            self.critical_count = 0
            self.high_count = 0
            self.medium_count = 0
            self.low_count = 0
            self.info_count = 0

            # Count vulnerabilities by severity
            for detector_result in self.raw_results.get("detector_results", []):
                for vulnerability in detector_result.get("vulnerabilities", []):
                    severity = vulnerability.get("severity", "info")
                    if severity == "critical":
                        self.critical_count += 1
                    elif severity == "high":
                        self.high_count += 1
                    elif severity == "medium":
                        self.medium_count += 1
                    elif severity == "low":
                        self.low_count += 1
                    else:
                        self.info_count += 1

            self.total_vulnerabilities = (
                self.critical_count
                + self.high_count
                + self.medium_count
                + self.low_count
                + self.info_count
            )

            self.save(
                update_fields=[
                    "critical_count",
                    "high_count",
                    "medium_count",
                    "low_count",
                    "info_count",
                    "total_vulnerabilities",
                ]
            )

        except Exception as e:
            print(f"Error updating vulnerability counts: {e}")


class Vulnerability(models.Model):
    """Individual vulnerability findings."""

    scan_result = models.ForeignKey(
        ScanResult, on_delete=models.CASCADE, related_name="vulnerabilities"
    )
    detector_name = models.CharField(max_length=100)
    vulnerability_type = models.CharField(max_length=200)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    description = models.TextField()
    evidence = models.TextField()
    remediation = models.TextField()

    # Additional metadata
    location = models.CharField(
        max_length=500, blank=True
    )  # URL or endpoint where found
    parameter = models.CharField(
        max_length=200, blank=True
    )  # Parameter name if applicable

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.vulnerability_type} - {self.severity}"

    class Meta:
        ordering = ["-severity", "vulnerability_type"]
        verbose_name_plural = "Vulnerabilities"
        db_table = "vulnerabilities"
        indexes = [
            models.Index(fields=["severity"]),
            models.Index(fields=["scan_result", "severity"]),
        ]


class ScanSchedule(models.Model):
    """Scheduled recurring scans."""

    name = models.CharField(max_length=100)
    target_url = models.URLField(max_length=500)
    scan_profile = models.ForeignKey(ScanProfile, on_delete=models.CASCADE)
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    is_active = models.BooleanField(default=True)
    next_scan = models.DateTimeField()
    last_scan = models.ForeignKey(
        ScanResult,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scheduled_scans",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        db_table = "scan_schedules"
        ordering = ["name"]
