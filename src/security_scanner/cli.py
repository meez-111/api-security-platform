#!/usr/bin/env python3
"""
HorseSec CLI - Command Line Interface for Security Scanning
"""

import asyncio
import argparse
import sys
import json
import os
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional

# Import the new HTML reporter
from security_scanner.reporters.html_reporter import HTMLReporter
from security_scanner.core.models import ScanConfig
from security_scanner.core.scanner import SecurityScanner, create_security_scanner


def print_progress(percent: int, message: str):
    """Print progress updates."""
    print(f"🔄 [{percent}%] {message}")


def print_result(result, output_format: str = "text"):
    """Print scan results in the specified format."""
    if output_format == "json":
        print(json.dumps(result.dict(), indent=2))
    elif output_format == "html":
        # HTML output is now handled separately via HTMLReporter
        pass
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
    parser.add_argument("--output", "-o", help="Output file path for report")
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

        # Generate output based on format
        if args.format == "html":
            # Use the new HTML reporter
            reporter = HTMLReporter()

            # Determine output file path
            if args.output:
                output_path = args.output
            else:
                # Generate automatic filename using the reporter's method
                output_path = reporter._get_output_path(result, "html")

            try:
                # Generate the professional HTML report
                report_path = reporter.generate(result, output_path)

                # Get absolute path for clarity
                abs_path = os.path.abspath(report_path)

                print(f"🎨 Professional HTML report generated: {report_path}")
                print(f"📁 Absolute path: {abs_path}")
                print("\n✨ Features included:")
                print("   • Dark/Light mode toggle 🌙/☀️")
                print("   • Interactive charts and filtering 📊")
                print("   • Collapsible sections with smooth animations 🎭")
                print("   • Mobile-responsive design 📱")
                print("   • Professional security branding 🛡️")

            except Exception as reporter_error:
                print(f"❌ Failed to generate HTML report: {reporter_error}")
                # Fallback to text output
                print("\nFalling back to text format...")
                print_result(result, "text")

        elif args.format == "json":
            # Print JSON to console
            print(json.dumps(result.dict(), indent=2))

            # Also save to file if output path specified
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(result.dict(), f, indent=2)
                print(f"💾 JSON report saved to: {args.output}")

        else:
            # Text format
            print_result(result, "text")

            # Save to file if output path specified
            if args.output:
                # Simple text file output
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(f"HorseSec Security Scan Report\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Target: {result.target_url}\n")
                    f.write(f"Scan Date: {result.timestamp}\n")
                    f.write(f"Risk Score: {result.risk_score}/10\n")
                    f.write(f"Duration: {result.scan_duration:.2f}s\n")
                    f.write(f"Vulnerabilities Found: {result.total_vulnerabilities}\n")
                    f.write("=" * 50 + "\n\n")

                    for detector in result.detector_results:
                        f.write(f"{detector.detector_name}:\n")
                        if detector.vulnerabilities:
                            for vuln in detector.vulnerabilities:
                                f.write(f"  - {vuln.type} ({vuln.severity.value})\n")
                                f.write(f"    Description: {vuln.description}\n")
                                f.write(f"    Evidence: {vuln.evidence}\n")
                                f.write(f"    Remediation: {vuln.remediation}\n\n")
                        else:
                            f.write("  No vulnerabilities found\n\n")

                print(f"💾 Text report saved to: {args.output}")

    except Exception as e:
        print(f"❌ Scan failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
