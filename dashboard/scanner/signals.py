from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import ScanResult, Vulnerability


@receiver(post_save, sender=ScanResult)
def update_vulnerability_counts(sender, instance, **kwargs):
    """
    Signal to update vulnerability counts when a ScanResult is saved.
    """
    if instance.raw_results and instance.status == "completed":
        instance.update_vulnerability_counts()


@receiver(post_save, sender=ScanResult)
def create_vulnerability_records(sender, instance, **kwargs):
    """
    Signal to create vulnerability records when a ScanResult is completed.
    """
    if (
        instance.raw_results
        and instance.status == "completed"
        and not instance.vulnerabilities.exists()
    ):
        from .models import Vulnerability

        # Create vulnerability records from raw results
        for detector_result in instance.raw_results.get("detector_results", []):
            for vulnerability_data in detector_result.get("vulnerabilities", []):
                Vulnerability.objects.create(
                    scan_result=instance,
                    detector_name=detector_result.get("detector_name", "Unknown"),
                    vulnerability_type=vulnerability_data.get("type", "Unknown"),
                    severity=vulnerability_data.get("severity", "info"),
                    description=vulnerability_data.get("description", ""),
                    evidence=vulnerability_data.get("evidence", ""),
                    remediation=vulnerability_data.get("remediation", ""),
                )
