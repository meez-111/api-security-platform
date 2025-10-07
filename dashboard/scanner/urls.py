from django.urls import path
from . import views

app_name = "scanner"

urlpatterns = [
    # Dashboard and scanning
    path("", views.dashboard, name="dashboard"),
    path("scan/new/", views.new_scan, name="new_scan"),
    path("scan/<int:pk>/", views.scan_detail, name="scan_detail"),
    path("scan/<int:pk>/results/", views.scan_results, name="scan_results"),
    # Scan management
    path("scans/", views.scan_list, name="scan_list"),
    path("scan/<int:pk>/delete/", views.scan_delete, name="scan_delete"),
    # Profiles
    path("profiles/", views.profile_list, name="profile_list"),
    # API endpoints
    path("api/scan/<int:pk>/status/", views.scan_status_api, name="scan_status_api"),
    path(
        "api/scan/<int:pk>/progress/", views.scan_progress_api, name="scan_progress_api"
    ),
]
