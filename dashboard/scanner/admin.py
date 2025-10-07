from django.contrib import admin
from django.utils.html import format_html
from .models import ScanProfile, ScanResult, Vulnerability, ScanSchedule


@admin.register(ScanProfile)
class ScanProfileAdmin(admin.ModelAdmin):
    list_display = ["name", "is_default", "created_at", "updated_at"]
    list_filter = ["is_default", "created_at"]
    search_fields = ["name", "description"]
    readonly_fields = ["created_at", "updated_at"]

    fieldsets = (
        (None, {"fields": ("name", "description", "is_default")}),
        ("Configuration", {"fields": ("config",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = [
        "target_url_display",
        "user",
        "status_badge",
        "vulnerability_count",
        "risk_score_display",
        "duration_display",
        "created_at",
    ]
    list_filter = ["status", "created_at", "user", "scan_profile"]
    search_fields = ["target_url", "error_message"]
    readonly_fields = ["created_at", "started_at", "completed_at"]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Scan Information",
            {"fields": ("target_url", "user", "scan_profile", "status")},
        ),
        (
            "Results",
            {
                "fields": (
                    "total_vulnerabilities",
                    "risk_score",
                    "scan_duration",
                    "critical_count",
                    "high_count",
                    "medium_count",
                    "low_count",
                    "info_count",
                )
            },
        ),
        (
            "Raw Data",
            {"fields": ("scan_config", "raw_results"), "classes": ("collapse",)},
        ),
        ("Timestamps", {"fields": ("created_at", "started_at", "completed_at")}),
        ("Error Information", {"fields": ("error_message",), "classes": ("collapse",)}),
    )

    def target_url_display(self, obj):
        if len(obj.target_url) > 50:
            return format_html("<code>{}</code>", obj.target_url[:50] + "...")
        return format_html("<code>{}</code>", obj.target_url)

    target_url_display.short_description = "Target URL"

    def status_badge(self, obj):
        colors = {
            "completed": "green",
            "running": "blue",
            "failed": "red",
            "queued": "gray",
            "cancelled": "orange",
        }
        color = colors.get(obj.status, "gray")
        return format_html(
            '<span style="background: {0}; color: white; padding: 2px 8px; border-radius: 10px; font-size: 12px;">{1}</span>',
            color,
            obj.status.upper(),
        )

    status_badge.short_description = "Status"

    def vulnerability_count(self, obj):
        if obj.status == "completed":
            color = "red" if obj.total_vulnerabilities > 0 else "green"
            return format_html(
                '<span style="color: {0}; font-weight: bold;">{1}</span>',
                color,
                obj.total_vulnerabilities,
            )
        return "-"

    vulnerability_count.short_description = "Vulns"

    def risk_score_display(self, obj):
        if obj.status == "completed":
            color = (
                "red"
                if obj.risk_score >= 7.5
                else "orange" if obj.risk_score >= 5 else "green"
            )
            # Format the score first, then pass to format_html
            formatted_score = f"{obj.risk_score:.1f}"
            return format_html(
                '<span style="color: {0}; font-weight: bold;">{1}/10</span>',
                color,
                formatted_score,
            )
        return "-"

    risk_score_display.short_description = "Risk Score"

    def duration_display(self, obj):
        if obj.status == "completed":
            return f"{obj.scan_duration:.1f}s"
        return "-"

    duration_display.short_description = "Duration"


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = [
        "vulnerability_type",
        "severity_badge",
        "detector_name",
        "scan_result_link",
        "created_at",
    ]
    list_filter = ["severity", "detector_name", "created_at"]
    search_fields = ["vulnerability_type", "description", "evidence"]
    readonly_fields = ["created_at"]

    def severity_badge(self, obj):
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }
        color = colors.get(obj.severity, "gray")
        text_color = "white" if obj.severity in ["critical", "high"] else "black"
        return format_html(
            '<span style="background: {0}; color: {1}; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: bold;">{2}</span>',
            color,
            text_color,
            obj.severity.upper(),
        )

    severity_badge.short_description = "Severity"

    def scan_result_link(self, obj):
        url = f"/admin/scanner/scanresult/{obj.scan_result.id}/change/"
        display_text = (
            obj.scan_result.target_url[:30] + "..."
            if len(obj.scan_result.target_url) > 30
            else obj.scan_result.target_url
        )
        return format_html('<a href="{0}">{1}</a>', url, display_text)

    scan_result_link.short_description = "Scan Result"


@admin.register(ScanSchedule)
class ScanScheduleAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "target_url",
        "scan_profile",
        "frequency",
        "is_active",
        "next_scan",
    ]
    list_filter = ["frequency", "is_active", "created_at"]
    search_fields = ["name", "target_url"]
    readonly_fields = ["created_at", "updated_at"]
