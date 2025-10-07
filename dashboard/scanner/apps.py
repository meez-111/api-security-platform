from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanner"
    verbose_name = "Security Scanner"

    def ready(self):
        """
        Import signals when the app is ready.
        This will fail silently if signals module doesn't exist yet.
        """
        try:
            import scanner.signals
        except ImportError:
            # Signals module doesn't exist yet, that's ok
            pass
