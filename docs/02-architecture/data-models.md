# Data Models

## Overview
This document describes the core data structures used by HorseSec API Security Scanner.

## Vulnerability
Represents a single security issue found during scanning.

**Fields:**
- `id`: Unique identifier for tracking
- `type`: Vulnerability category (jwt, cors, headers)
- `title`: Short, descriptive title
- `description`: Detailed explanation of the issue
- `severity`: Risk level (Critical/High/Medium/Low)
- `evidence`: Proof that the vulnerability exists
- `remediation`: Step-by-step fix instructions
- `location`: Where the issue was found
- `cvss_score`: Standardized risk score (0-10)

## DetectorResult
Results from a single vulnerability detector.

**Fields:**
- `detector_name`: Name of the detector that ran
- `vulnerabilities`: List of found vulnerabilities
- `scan_duration`: How long the scan took
- `error`: Any errors encountered

## ScanConfig
User configuration for security scans.

**Fields:**
- `target_url`: API endpoint to scan
- `timeout`: Request timeout in seconds
- `follow_redirects`: Whether to follow redirects
- `headers`: Custom headers to include
- `verify_ssl`: SSL certificate verification
- `scan_jwt`: Enable JWT detector
- `scan_headers`: Enable headers detector  
- `scan_cors`: Enable CORS detector

## ScanResult
Complete results from a security scan.

**Fields:**
- `target_url`: Scanned API endpoint
- `scan_config`: Configuration used
- `detector_results`: Results from all detectors
- `total_vulnerabilities`: Count of all findings
- `risk_score`: Overall risk score (0-10)
- `scan_duration`: Total scan time
- `timestamp`: When scan was run