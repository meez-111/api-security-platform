#!/usr/bin/env python3
"""
Enhanced CLI for HorseSec API Security Scanner with configuration files and progress.
"""

import asyncio
import sys
import argparse
from pathlib import Path

from security_scanner.core.models import ScanConfig
from security_scanner.core.scanner import create_security_scanner
from security_scanner.core.config_manager import ConfigManager
from security_scanner.reporters import HTMLReporter, JSONReporter


def print_progress(percentage: int, message: str):
    """Print progress updates."""
    print(f"[{percentage}%] {message}")


async def main():
    """Main CLI entry point with enhanced argument parsing."""
    parser = argparse.ArgumentParser(
        description="🐎 HorseSec API Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://api.example.com
  %(prog)s https://api.example.com --format html
  %(prog)s https://api.example.com --format json --output custom_report.json
  %(prog)s https://api.example.com --no-jwt --timeout 60
  %(prog)s --config config.yaml
  %(prog)s --quick-scan https://api.example.com
        """,
    )

    # Target selection
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("target_url", nargs="?", help="Target API URL to scan")
    target_group.add_argument(
        "--config", "-c", help="Load configuration from YAML file"
    )

    # Scan modes
    scan_mode = parser.add_mutually_exclusive_group()
    scan_mode.add_argument(
        "--quick-scan",
        action="store_true",
        help="Run a quick security scan (headers only)",
    )
    scan_mode.add_argument(
        "--full-scan",
        action="store_true",
        help="Run a comprehensive security scan (all detectors)",
    )

    # Output options
    parser.add_argument(
        "--format",
        "-f",
        choices=["html", "json"],
        help="Generate report in specified format",
    )
    parser.add_argument("--output", "-o", help="Custom output file path for report")
    parser.add_argument(
        "--no-progress", action="store_true", help="Disable progress indicators"
    )

    # Scan configuration
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--no-jwt",
        action="store_false",
        dest="scan_jwt",
        help="Disable JWT vulnerability detection",
    )
    parser.add_argument(
        "--no-headers",
        action="store_false",
        dest="scan_headers",
        help="Disable security headers detection",
    )
    parser.add_argument(
        "--no-cors",
        action="store_false",
        dest="scan_cors",
        help="Disable CORS misconfiguration detection",
    )
    parser.add_argument(
        "--sql-injection",
        action="store_true",
        dest="scan_sql_injection",
        help="Enable SQL injection detection (experimental)",
    )
    parser.add_argument(
        "--xss",
        action="store_true",
        dest="scan_xss",
        help="Enable XSS detection (experimental)",
    )

    args = parser.parse_args()

    # Create scan configuration based on arguments
    if args.config:
        # Load from configuration file
        if not Path(args.config).exists():
            print(f"❌ Configuration file not found: {args.config}")
            sys.exit(1)

        config = ConfigManager.load_from_yaml(args.config)
        if args.target_url:
            config.target_url = args.target_url

    elif args.quick_scan:
        # Quick scan mode
        config = ConfigManager.create_quick_scan_config()
        config.target_url = args.target_url

    elif args.full_scan:
        # Full scan mode
        config = ConfigManager.create_full_scan_config()
        config.target_url = args.target_url
        config.scan_sql_injection = True
        config.scan_xss = True

    else:
        # Standard scan with command line arguments
        config = ScanConfig(
            target_url=args.target_url,
            timeout=args.timeout,
            follow_redirects=True,
            verify_ssl=True,
            scan_jwt=args.scan_jwt,
            scan_headers=args.scan_headers,
            scan_cors=args.scan_cors,
            scan_sql_injection=args.scan_sql_injection,
            scan_xss=args.scan_xss,
        )

    print("🐎 HorseSec API Security Scanner")
    print("=" * 50)

    try:
        # Create and run scanner
        scanner = create_security_scanner(config)

        # Run scan with or without progress indicators
        if args.no_progress:
            result = await scanner.scan()
        else:
            result = await scanner.scan(progress_callback=print_progress)

        # Print summary to console
        print_summary(result)

        # Generate report if requested
        if args.format:
            report_path = generate_report(result, args.format, args.output)
            print(f"📄 Report generated: {report_path}")

    except Exception as e:
        print(f"\n❌ Scan failed: {str(e)}")
        sys.exit(1)


def print_summary(scan_result):
    """Print comprehensive scan summary to console."""
    print("\n" + "=" * 50)
    print("📋 SCAN SUMMARY")
    print("=" * 50)
    print(f"Target: {scan_result.target_url}")
    print(f"Duration: {scan_result.scan_duration:.2f}s")
    print(f"Vulnerabilities: {scan_result.total_vulnerabilities}")
    print(f"Risk Score: {scan_result.risk_score:.1f}/10.0")

    # Print vulnerability breakdown
    if scan_result.total_vulnerabilities > 0:
        severity_counts = {}
        for detector_result in scan_result.detector_results:
            for vuln in detector_result.vulnerabilities:
                severity = vuln.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print(f"Breakdown: {severity_counts}")

    # Print detailed findings
    if scan_result.total_vulnerabilities > 0:
        print("\n🔍 VULNERABILITIES FOUND:")
        for detector_result in scan_result.detector_results:
            if detector_result.vulnerabilities:
                print(f"\n{detector_result.detector_name}:")
                for vuln in detector_result.vulnerabilities:
                    severity_icon = {
                        "critical": "🚨",
                        "high": "🔴",
                        "medium": "🟡",
                        "low": "🔵",
                    }.get(vuln.severity.value, "⚪")

                    print(f"  {severity_icon} {vuln.title} ({vuln.severity.value})")
                    print(f"     📍 {vuln.location}")
                    print(f"     📝 {vuln.description[:100]}...")
    else:
        print("\n✅ No vulnerabilities found!")


def generate_report(scan_result, format: str, output_path: str = None) -> str:
    """Generate report in specified format."""
    if format == "html":
        reporter = HTMLReporter()
    elif format == "json":
        reporter = JSONReporter()
    else:
        raise ValueError(f"Unsupported format: {format}")

    return reporter.generate(scan_result, output_path)


if __name__ == "__main__":
    asyncio.run(main())
