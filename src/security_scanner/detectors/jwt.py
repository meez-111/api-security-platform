import time
from typing import List, Optional
import jwt
from jwt import PyJWTError

from security_scanner.detectors.base import BaseDetector
from security_scanner.core.models import (
    DetectorResult,
    ScanConfig,
    Vulnerability,
    Severity,
)


class JWTDetector(BaseDetector):
    """
    JWT Vulnerability Detector

    Checks for common JWT security misconfigurations and vulnerabilities
    including weak algorithms, missing expiration, and token validation issues.
    """

    def __init__(self):
        super().__init__()
        self.name = "JWTDetector"
        self.description = "Detects JWT token vulnerabilities and misconfigurations"
        self.supported_types = ["jwt", "authentication"]

    async def scan(self, target_url: str, config: ScanConfig) -> DetectorResult:
        """
        Scan for JWT vulnerabilities in the target API.

        This implementation will:
        1. Look for JWT tokens in requests/responses
        2. Analyze token strength and configuration
        3. Report found vulnerabilities

        Args:
            target_url: The URL to scan for vulnerabilities
            config: Scan configuration settings

        Returns:
            DetectorResult: Contains found vulnerabilities or errors
        """
        start_time = time.time()
        vulnerabilities: List[Vulnerability] = []

        try:
            # For now, we'll simulate finding some JWT tokens
            # In the real implementation, we'll extract from HTTP traffic
            vulnerabilities = await self._analyze_jwt_tokens(target_url, config)

        except Exception as e:
            error_msg = f"JWT detector failed: {str(e)}"
            return self.create_detector_result(error=error_msg)

        scan_duration = time.time() - start_time
        result = self.create_detector_result(vulnerabilities=vulnerabilities)
        result.scan_duration = scan_duration

        return result

    async def _analyze_jwt_tokens(
        self, target_url: str, config: ScanConfig
    ) -> List[Vulnerability]:
        """
        Analyze JWT tokens for security vulnerabilities using real HTTP responses.
        """
        vulnerabilities: List[Vulnerability] = []

        try:
            # Use HTTP client to analyze actual responses
            from security_scanner.http.client import HTTPClient

            async with HTTPClient(config) as client:
                analysis = await client.get_response_analysis(target_url)

                if "error" in analysis:
                    return vulnerabilities

                jwt_tokens = analysis["jwt_tokens"]

                if not jwt_tokens:
                    # No JWT tokens found - don't report any JWT vulnerabilities
                    return vulnerabilities

                # Analyze found JWT tokens
                for token in jwt_tokens:
                    token_vulnerabilities = await self._analyze_single_token(token)
                    vulnerabilities.extend(token_vulnerabilities)

                # If we found tokens but no specific vulnerabilities, report as informational
                if jwt_tokens and not vulnerabilities:
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="jwt",
                            title="JWT Tokens Found",
                            description="JWT tokens were found but no critical vulnerabilities detected",
                            severity=Severity.LOW,
                            evidence=f"Found {len(jwt_tokens)} JWT token(s) in response",
                            remediation="Ensure tokens use strong algorithms and proper expiration",
                            location="Authorization headers",
                        )
                    )

        except Exception as e:
            # If analysis fails, don't report false positives
            print(f"JWT analysis error: {e}")

        return vulnerabilities

    async def _analyze_single_token(self, token: str) -> List[Vulnerability]:
        """
        Analyze a single JWT token for vulnerabilities.
        """
        vulnerabilities = []

        try:
            # Decode token header to check algorithm
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg", "")

            # Check for 'none' algorithm (Critical)
            if algorithm.lower() == "none":
                vulnerabilities.append(
                    self.create_vulnerability(
                        vuln_type="jwt",
                        title="JWT 'none' Algorithm Vulnerability",
                        description="JWT tokens using 'none' algorithm allow anyone to forge valid tokens",
                        severity=Severity.CRITICAL,
                        evidence=f"Token uses 'alg': 'none'. Token: {token[:50]}...",
                        remediation="Never use 'none' algorithm in production. Always require signature verification.",
                        location="JWT token header",
                    )
                )

            # Decode payload to check expiration
            payload = self._decode_jwt_token(token)
            if payload:
                # Check for missing expiration (High)
                if "exp" not in payload:
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="jwt",
                            title="JWT Token Without Expiration",
                            description="JWT tokens do not have an expiration time (exp claim), allowing indefinite access",
                            severity=Severity.HIGH,
                            evidence=f"Token missing 'exp' claim. Payload: {str(payload)[:100]}...",
                            remediation="Always set reasonable expiration times (15-30 minutes) in JWT 'exp' claim",
                            location="JWT token payload",
                        )
                    )

                # Check for weak algorithm (Medium)
                weak_algorithms = [
                    "HS256",
                    "HS384",
                    "HS512",
                ]  # Can be weak if secret is poor
                if algorithm in weak_algorithms:
                    vulnerabilities.append(
                        self.create_vulnerability(
                            vuln_type="jwt",
                            title="JWT Using Symmetric Algorithm",
                            description="JWT tokens use symmetric algorithm (HS256) which may be vulnerable if secret is weak",
                            severity=Severity.MEDIUM,
                            evidence=f"Token uses '{algorithm}' algorithm",
                            remediation="Consider using asymmetric algorithms like RS256 with proper key management",
                            location="JWT token header",
                        )
                    )

        except Exception as e:
            print(f"Token analysis error: {e}")

        return vulnerabilities

    def _decode_jwt_token(self, token: str) -> Optional[dict]:
        """
        Safely decode a JWT token without verification.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload or None if invalid
        """
        try:
            # Decode without verification to examine structure
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except PyJWTError:
            return None

    def _check_algorithm_strength(self, token: str) -> bool:
        """
        Check if JWT token uses strong algorithms.

        Args:
            token: JWT token to analyze

        Returns:
            True if strong algorithm, False if weak
        """
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg", "")

            # Weak algorithms to flag
            weak_algorithms = [
                "none",
                "HS256",
            ]  # In real implementation, we'd check key strength

            return algorithm not in weak_algorithms
        except PyJWTError:
            return False

    def _check_token_expiration(self, token: str) -> bool:
        """
        Check if JWT token has expiration set.

        Args:
            token: JWT token to analyze

        Returns:
            True if expiration is set, False otherwise
        """
        try:
            payload = self._decode_jwt_token(token)
            if payload and "exp" in payload:
                return True
            return False
        except PyJWTError:
            return False


# Factory function to create JWT detector instance
def create_jwt_detector() -> JWTDetector:
    """Factory function to create and return JWT detector instance"""
    return JWTDetector()
