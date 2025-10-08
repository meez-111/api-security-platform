import asyncio
import random
import time
from typing import List, Dict, Any
from urllib.parse import urlencode, parse_qs, urlparse

from security_scanner.core.models import (
    ScanConfig,
    DetectorResult,
    Vulnerability,
    Severity,
)
from security_scanner.detectors.base import BaseDetector


class SQLInjectionDetector(BaseDetector):
    """
    Advanced SQL Injection vulnerability detector with reduced false positives.
    """

    def __init__(self):
        super().__init__()
        self.name = "SQL Injection"
        self.description = (
            "Detects SQL injection vulnerabilities with advanced heuristics"
        )
        self.supported_types = [
            "boolean_blind_sqli",
            "error_based_sqli",
            "time_based_sqli",
        ]

        # More sophisticated payloads that are less likely to trigger false positives
        self.payloads = {
            "syntax_test": ["'", '"', "`", "--", "/*", "#"],
            "boolean_test": [
                "' OR '1'='1'--",
                "' OR 1=1--",
                "admin'--",
                "' OR 'a'='a'--",
            ],
            "union_test": ["' UNION SELECT NULL--", "' UNION SELECT 1,2,3--"],
            "error_based": [
                "' AND 1=CAST(0x5f5f5f5f AS INT)--",
                "' AND EXTRACTVALUE(0,CONCAT(0x5c,0x7178627171,(SELECT (ELT(1=1,1))),0x71707a6271))--",
            ],
        }

        # Common SQL error patterns that indicate actual SQL injection
        self.sql_error_patterns = [
            # MySQL
            r"mysql_(fetch_array|num_rows|result|error)",
            r"you have an error in your sql syntax",
            r"warning: mysql",
            # PostgreSQL
            r"postgresql.*error",
            r"pg_.*error",
            # SQL Server
            r"microsoft.*(odbc|sql server)",
            r"sqlserver.*driver",
            # Oracle
            r"ora-\d{5}",
            r"oracle.*error",
            # Generic SQL
            r"sql (command|syntax|statement)",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"invalid query",
        ]

        # False positive patterns (common in normal web pages)
        self.false_positive_patterns = [
            r"mysql_fetch_array",  # Often in documentation
            r"sql.*example",  # SQL examples
            r"database.*example",  # Database examples
            r"select.*from",  # Common in documentation
            r"sql.*tutorial",  # Tutorial content
        ]

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for SQL injection vulnerabilities with reduced false positives.
        """
        vulnerabilities = []

        try:
            # Use the HTTP client from the scanner
            from security_scanner.http.client import HTTPClient

            async with HTTPClient(config) as client:
                # Get baseline response for comparison
                baseline_response = await client.get(target_url)
                baseline_content = baseline_response.text.lower()

                # Test GET parameters
                get_vulns = await self._test_get_parameters(
                    target_url, client, baseline_content
                )
                vulnerabilities.extend(get_vulns)

                # Test POST parameters if applicable
                post_vulns = await self._test_post_parameters(
                    target_url, client, baseline_content
                )
                vulnerabilities.extend(post_vulns)

        except Exception as e:
            error_msg = f"SQL Injection scan failed: {str(e)}"
            return self.create_detector_result(error=error_msg)

        return self.create_detector_result(vulnerabilities=vulnerabilities)

    async def _test_get_parameters(
        self, target_url: str, client, baseline_content: str
    ) -> List[Vulnerability]:
        """Test GET parameters for SQL injection with improved detection."""
        vulnerabilities = []
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)

        # If no parameters, create test parameters but be conservative
        if not query_params:
            # Only test common parameters that are likely to be used in SQL queries
            test_params = {"id": ["1"], "user": ["test"], "search": ["test"]}
        else:
            test_params = query_params

        tested_params = set()

        for param_name in test_params.keys():
            if param_name in tested_params:
                continue

            print(f"   Testing parameter: {param_name}")
            tested_params.add(param_name)

            # Test with syntax-breaking payloads first
            syntax_vuln = await self._test_parameter_syntax(
                target_url, param_name, client, baseline_content
            )
            if syntax_vuln:
                vulnerabilities.append(syntax_vuln)
                continue  # Don't test further if we found a clear vulnerability

            # Test with boolean-based payloads
            boolean_vuln = await self._test_parameter_boolean(
                target_url, param_name, client, baseline_content
            )
            if boolean_vuln:
                vulnerabilities.append(boolean_vuln)

        return vulnerabilities

    async def _test_parameter_syntax(
        self, target_url: str, param_name: str, client, baseline_content: str
    ) -> Vulnerability:
        """Test parameter with syntax-breaking payloads."""
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)

        for payload in self.payloads["syntax_test"]:
            test_params = query_params.copy()
            test_params[param_name] = [payload]

            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"

            try:
                response = await client.get(test_url)

                # Check for SQL errors with high confidence
                if self._has_high_confidence_sql_errors(
                    response.text, baseline_content
                ):
                    return self.create_vulnerability(
                        vuln_type="error_based_sqli",
                        title="Potential SQL Injection (Error-Based)",
                        description=f"Parameter '{param_name}' may be vulnerable to SQL injection - triggered database errors",
                        severity=Severity.HIGH,
                        evidence=f"Payload '{payload}' triggered database error messages",
                        remediation="Use parameterized queries or prepared statements. Implement proper input validation and escaping.",
                        location=f"GET parameter: {param_name}",
                        cvss_score=8.2,
                    )

            except Exception as e:
                # Connection errors might indicate SQL injection breaking the application
                if "timeout" in str(e).lower() or "connection" in str(e).lower():
                    return self.create_vulnerability(
                        vuln_type="error_based_sqli",
                        title="Potential SQL Injection (Application Error)",
                        description=f"Parameter '{param_name}' caused application errors when testing for SQL injection",
                        severity=Severity.MEDIUM,
                        evidence=f"Payload '{payload}' caused application to respond with errors: {str(e)}",
                        remediation="Use parameterized queries or prepared statements. Implement proper error handling.",
                        location=f"GET parameter: {param_name}",
                        cvss_score=6.5,
                    )

        return None

    async def _test_parameter_boolean(
        self, target_url: str, param_name: str, client, baseline_content: str
    ) -> Vulnerability:
        """Test parameter with boolean-based payloads."""
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)

        for payload in self.payloads["boolean_test"]:
            test_params = query_params.copy()
            test_params[param_name] = [payload]

            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"

            try:
                response = await client.get(test_url)
                test_content = response.text.lower()

                # Check for content differences that might indicate successful injection
                if self._has_suspicious_content_changes(test_content, baseline_content):
                    # Verify it's not a false positive
                    if not self._is_likely_false_positive(test_content):
                        return self.create_vulnerability(
                            vuln_type="boolean_blind_sqli",
                            title="Potential SQL Injection (Boolean-Based)",
                            description=f"Parameter '{param_name}' may be vulnerable to boolean-based SQL injection",
                            severity=Severity.HIGH,
                            evidence=f"Payload '{payload}' caused significant content changes indicating potential injection",
                            remediation="Use parameterized queries or prepared statements. Implement proper input validation.",
                            location=f"GET parameter: {param_name}",
                            cvss_score=7.5,
                        )

            except Exception as e:
                # Log but don't create vulnerability from connection errors for boolean tests
                print(
                    f"      Note: Error testing {param_name} with boolean payload: {e}"
                )

        return None

    async def _test_post_parameters(
        self, target_url: str, client, baseline_content: str
    ) -> List[Vulnerability]:
        """Test POST parameters for SQL injection (placeholder for future implementation)."""
        # This would be similar to GET testing but with POST requests
        # For now, return empty list since we're focusing on GET improvements
        return []

    def _has_high_confidence_sql_errors(
        self, response_text: str, baseline_content: str
    ) -> bool:
        """Check for high-confidence SQL error indicators."""
        import re

        content_lower = response_text.lower()

        # Check for actual SQL error patterns
        sql_errors_found = 0
        for pattern in self.sql_error_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                sql_errors_found += 1

        # Require multiple SQL error indicators to reduce false positives
        if sql_errors_found >= 2:
            # Check if these errors are significantly different from baseline
            baseline_errors = 0
            for pattern in self.sql_error_patterns:
                if re.search(pattern, baseline_content, re.IGNORECASE):
                    baseline_errors += 1

            # Only report if we found significantly more errors than baseline
            return sql_errors_found > baseline_errors + 1

        return False

    def _has_suspicious_content_changes(
        self, test_content: str, baseline_content: str
    ) -> bool:
        """Check for suspicious content changes that might indicate SQL injection."""
        # Simple length-based heuristic - significant content changes
        length_change = abs(len(test_content) - len(baseline_content))

        # If content length changed significantly (more than 50%)
        if length_change > len(baseline_content) * 0.5:
            return True

        # Check for complete content changes (different page entirely)
        test_words = set(test_content.lower().split()[:50])  # First 50 words
        baseline_words = set(baseline_content.lower().split()[:50])

        similarity = (
            len(test_words.intersection(baseline_words)) / len(baseline_words)
            if baseline_words
            else 0
        )

        # If content is very different (less than 30% similarity)
        return similarity < 0.3

    def _is_likely_false_positive(self, content: str) -> bool:
        """Check if the content matches common false positive patterns."""
        import re

        content_lower = content.lower()

        for pattern in self.false_positive_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True

        # Check for common error pages that aren't SQL-related
        common_errors = [
            "page not found",
            "404 error",
            "internal server error",
            "service unavailable",
            "access denied",
        ]

        if any(error in content_lower for error in common_errors):
            return True

        return False

    def _detect_sqli_indicators(self, content: str) -> bool:
        """Legacy method - kept for compatibility but uses improved logic."""
        return self._has_high_confidence_sql_errors(content, "")
