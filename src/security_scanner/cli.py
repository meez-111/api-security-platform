#!/usr/bin/env python3
"""
HorseSec CLI - Command Line Interface for Security Scanning
"""

import asyncio
import argparse
import sys
import json
from typing import Optional
from .core.models import ScanConfig
from .core.scanner import create_security_scanner


def print_progress(message: str):
    """Print progress updates."""
    print(f"🔄 {message}")


def print_result(result, output_format: str = "text"):
    """Print scan results in the specified format."""
    if output_format == "json":
        print(json.dumps(result.dict(), indent=2))
    elif output_format == "html":
        print(generate_html_report(result))
    else:  # text format
        print("\n" + "=" * 50)
        print("🐎 HorseSec Security Scan Results")
        print("=" * 50)
        print(f"🎯 Target: {result.target_url}")
        print(f"📊 Risk Score: {result.risk_score}/10")
        print(f"⏱️  Duration: {result.scan_duration:.2f}s")
        print(f"🔍 Vulnerabilities Found: {result.total_vulnerabilities}")
        print("-" * 50)

        for detector in result.detector_results:
            print(f"\n📋 {detector.detector_name}:")
            if detector.vulnerabilities:
                for vuln in detector.vulnerabilities:
                    print(f"   ⚠️  {vuln.type} ({vuln.severity.value})")
                    print(f"      📝 {vuln.description}")
                    print(f"      🔍 Evidence: {vuln.evidence}")
                    print(f"      💡 Fix: {vuln.remediation}")
                    print()
            else:
                print("   ✅ No vulnerabilities found")

        print("=" * 50)


def generate_html_report(result) -> str:
    """Generate HTML report for scan results."""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>HorseSec Security Report - {result.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .risk-score {{ font-size: 24px; font-weight: bold; }}
        .risk-high {{ color: #e74c3c; }}
        .risk-medium {{ color: #f39c12; }}
        .risk-low {{ color: #27ae60; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #f39c12; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #27ae60; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🐎 HorseSec Security Report</h1>
        <p><strong>Target:</strong> {result.target_url}</p>
        <p><strong>Scan Date:</strong> {result.timestamp}</p>
        <p><strong>Duration:</strong> {result.scan_duration:.2f} seconds</p>
    </div>
    
    <div class="risk-score {f'risk-{"" if result.risk_score >= 7 else "medium" if result.risk_score >= 4 else "low"}'}">
        Overall Risk Score: {result.risk_score}/10
    </div>
    
    <h2>Vulnerabilities Found: {result.total_vulnerabilities}</h2>
"""

    for detector in result.detector_results:
        if detector.vulnerabilities:
            html += f"<h3>🔍 {detector.detector_name}</h3>"
            for vuln in detector.vulnerabilities:
                severity_class = vuln.severity.value
                html += f"""
                <div class="vulnerability {severity_class}">
                    <h4>⚠️ {vuln.type} ({vuln.severity.value.upper()})</h4>
                    <p><strong>Description:</strong> {vuln.description}</p>
                    <p><strong>Evidence:</strong> {vuln.evidence}</p>
                    <p><strong>Remediation:</strong> {vuln.remediation}</p>
                </div>
                """

    html += """
</body>
</html>
"""
    return html


async def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="HorseSec Security Scanner")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    # Detector options
    parser.add_argument(
        "--no-headers", action="store_true", help="Skip security headers check"
    )
    parser.add_argument("--no-cors", action="store_true", help="Skip CORS check")
    parser.add_argument("--no-jwt", action="store_true", help="Skip JWT check")
    parser.add_argument(
        "--no-sqli", action="store_true", help="Skip SQL injection check"
    )
    parser.add_argument("--no-xss", action="store_true", help="Skip XSS check")

    args = parser.parse_args()

    # Create scan configuration
    config = ScanConfig(
        target_url=args.target,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        scan_headers=not args.no_headers,
        scan_cors=not args.no_cors,
        scan_jwt=not args.no_jwt,
        scan_sql_injection=not args.no_sqli,
        scan_xss=not args.no_xss,
    )

    print("🐎 HorseSec Security Scanner")
    print(f"🎯 Target: {args.target}")
    print(f"📊 Format: {args.format}")
    print("=" * 50)

    try:
        # Create and run scanner
        scanner = create_security_scanner(config)
        result = await scanner.scan(progress_callback=print_progress)

        # Print results
        print_result(result, args.format)

    except Exception as e:
        print(f"❌ Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
