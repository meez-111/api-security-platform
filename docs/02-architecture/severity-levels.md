# Vulnerability Severity Levels

## Overview
This document defines the severity levels used by HorseSec API Security Scanner to categorize discovered vulnerabilities. Severity is determined by potential impact and exploitability.

## Severity Levels

### 🚨 CRITICAL
**Impact:** Immediate system compromise or massive data breach  
**Response Time:** Drop everything and fix immediately  
**CVSS Score:** 9.0 - 10.0

**Examples:**
- JWT using 'none' algorithm (allows token forgery)
- CORS `Access-Control-Allow-Origin: *` with credentials enabled
- SQL Injection allowing full database access

### 🔴 HIGH  
**Impact:** Significant data exposure or system access  
**Response Time:** Fix within current sprint  
**CVSS Score:** 7.0 - 8.9

**Examples:**
- JWT tokens with no expiration
- Missing HSTS header on HTTPS sites
- CORS origin reflection with credentials

### 🟡 MEDIUM
**Impact:** Security weakness requiring specific conditions to exploit  
**Response Time:** Fix within next sprint  
**CVSS Score:** 4.0 - 6.9

**Examples:**
- JWT using weak algorithms with poor secrets
- Missing Content-Security-Policy header
- Overly broad CORS wildcard domains (`*.example.com`)

### 🔵 LOW
**Impact:** Best practice violations with minimal immediate risk  
**Response Time:** Fix when convenient  
**CVSS Score:** 0.1 - 3.9

**Examples:**
- JWT missing 'typ' field in header
- Server version disclosure in headers
- Missing CORS headers for public resources

## Assessment Criteria

### Exploitability
- **Critical:** Exploitable remotely without authentication
- **High:** Exploitable remotely with low privileges  
- **Medium:** Requires specific conditions or user interaction
- **Low:** Theoretical or difficult to exploit

### Impact
- **Critical:** Complete system compromise
- **High:** Significant data exposure
- **Medium:** Limited data exposure or system access
- **Low:** Information disclosure only

## Usage in Reports
All generated security reports will use these severity levels to help prioritize remediation efforts.