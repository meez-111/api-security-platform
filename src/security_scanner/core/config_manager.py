import yaml
import json
from pathlib import Path
from typing import Dict, Any
from security_scanner.core.models import ScanConfig


class ConfigManager:
    """
    Manages loading and saving scan configurations from files.
    """

    @staticmethod
    def load_from_yaml(file_path: str) -> ScanConfig:
        """
        Load scan configuration from a YAML file.

        Args:
            file_path: Path to YAML configuration file

        Returns:
            ScanConfig object
        """
        with open(file_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f)

        return ScanConfig(**config_data)

    @staticmethod
    def load_from_json(file_path: str) -> ScanConfig:
        """
        Load scan configuration from a JSON file.

        Args:
            file_path: Path to JSON configuration file

        Returns:
            ScanConfig object
        """
        with open(file_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        return ScanConfig(**config_data)

    @staticmethod
    def save_to_yaml(config: ScanConfig, file_path: str):
        """
        Save scan configuration to a YAML file.

        Args:
            config: ScanConfig to save
            file_path: Path to save YAML file
        """
        config_dict = config.dict()
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)

    @staticmethod
    def create_quick_scan_config() -> ScanConfig:
        """
        Create a quick scan configuration (minimal checks).

        Returns:
            Quick scan ScanConfig
        """
        return ScanConfig(
            target_url="https://api.example.com",
            timeout=15,
            follow_redirects=True,
            verify_ssl=True,
            scan_jwt=False,  # Skip JWT for speed
            scan_headers=True,
            scan_cors=False,  # Skip CORS for speed
        )

    @staticmethod
    def create_full_scan_config() -> ScanConfig:
        """
        Create a comprehensive scan configuration (all checks).

        Returns:
            Full scan ScanConfig
        """
        return ScanConfig(
            target_url="https://api.example.com",
            timeout=60,
            follow_redirects=True,
            headers={
                "User-Agent": "HorseSec-Scanner/1.0.0",
                "Accept": "application/json",
            },
            verify_ssl=True,
            scan_jwt=True,
            scan_headers=True,
            scan_cors=True,
        )
