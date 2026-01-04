"""DNSSEC validation engine."""

import dns.dnssec
import dns.rdatatype
import logging
from typing import List, Optional, Tuple
from datetime import datetime
from .models import SecurityIssue, Severity, IssueType, KeyInfo

logger = logging.getLogger(__name__)


class DNSSECValidator:
    """Performs DNSSEC signature and chain validation."""
    
    # RFC 8624 Algorithm Status
    RECOMMENDED_ALGORITHMS = {
        'ECDSAP256SHA256',  # 13
        'ECDSAP384SHA384',  # 14
        'ED25519',          # 15
        'ED448',            # 16
    }
    
    DEPRECATED_ALGORITHMS = {
        'RSAMD5',           # 1
        'RSASHA1',          # 5
        'RSASHA1NSEC3SHA1', # 7
    }
    
    NOT_RECOMMENDED = {
        'RSASHA256',        # 8
        'RSASHA512',        # 10
        'ECDSAP256SHA256',  # Optional but recommended
    }
    
    def __init__(self):
        """Initialize validator."""
        self.issues: List[SecurityIssue] = []
    
    def validate_signature(self, rrset, rrsigset, keys: dict) -> Tuple[bool, List[SecurityIssue]]:
        """Validate an RRset signature.
        
        Args:
            rrset: RRset to validate
            rrsigset: RRSIG records
            keys: Dictionary of DNSKEY records
            
        Returns:
            Tuple of (is_valid, issues)
        """
        issues = []
        
        try:
            dns.dnssec.validate(rrset, rrsigset, keys)
            return True, issues
        except dns.dnssec.ValidationFailure as e:
            issue = SecurityIssue(
                type=IssueType.CHAIN_INVALID,
                severity=Severity.CRITICAL,
                message=f"Signature validation failed: {str(e)}",
                details=str(e),
                remediation="Check DNSSEC configuration on authoritative nameserver",
            )
            issues.append(issue)
            return False, issues
        except Exception as e:
            issue = SecurityIssue(
                type=IssueType.CHAIN_INVALID,
                severity=Severity.HIGH,
                message=f"Validation error: {str(e)}",
                details=str(e),
            )
            issues.append(issue)
            return False, issues
    
    def check_signature_expiration(self, rrsig) -> List[SecurityIssue]:
        """Check if signatures are expired or expiring soon.
        
        Args:
            rrsig: RRSIG record
            
        Returns:
            List of issues found
        """
        issues = []
        
        if not hasattr(rrsig, 'expiration'):
            return issues
        
        expiration = datetime.utcfromtimestamp(rrsig.expiration)
        now = datetime.utcnow()
        days_until_expiry = (expiration - now).days
        
        if days_until_expiry < 0:
            issue = SecurityIssue(
                type=IssueType.SIGNATURE_EXPIRED,
                severity=Severity.CRITICAL,
                message=f"Signature expired {abs(days_until_expiry)} days ago",
                details=f"Expiration: {expiration.isoformat()}",
                remediation="Re-sign the zone immediately",
            )
            issues.append(issue)
        elif days_until_expiry < 7:
            issue = SecurityIssue(
                type=IssueType.EXPIRATION_WARNING,
                severity=Severity.HIGH,
                message=f"Signature expires in {days_until_expiry} days",
                details=f"Expiration: {expiration.isoformat()}",
                remediation="Plan re-signing within 7 days",
            )
            issues.append(issue)
        elif days_until_expiry < 30:
            issue = SecurityIssue(
                type=IssueType.EXPIRATION_WARNING,
                severity=Severity.MEDIUM,
                message=f"Signature expires in {days_until_expiry} days",
                details=f"Expiration: {expiration.isoformat()}",
                remediation="Schedule re-signing within 30 days",
            )
            issues.append(issue)
        
        return issues
    
    def check_algorithm_strength(self, algorithm: str) -> List[SecurityIssue]:
        """Check cryptographic algorithm strength per RFC 8624.
        
        Args:
            algorithm: Algorithm name or number
            
        Returns:
            List of issues found
        """
        issues = []
        
        algo_str = str(algorithm).upper() if isinstance(algorithm, int) else algorithm
        
        if algo_str in self.DEPRECATED_ALGORITHMS:
            issue = SecurityIssue(
                type=IssueType.ALGORITHM_WEAK,
                severity=Severity.CRITICAL,
                message=f"Algorithm {algo_str} is deprecated per RFC 8624",
                remediation=f"Migrate to {', '.join(self.RECOMMENDED_ALGORITHMS)}",
            )
            issues.append(issue)
        elif algo_str in self.NOT_RECOMMENDED:
            issue = SecurityIssue(
                type=IssueType.ALGORITHM_WEAK,
                severity=Severity.MEDIUM,
                message=f"Algorithm {algo_str} is not recommended per RFC 8624",
                remediation=f"Consider migrating to {', '.join(self.RECOMMENDED_ALGORITHMS)}",
            )
            issues.append(issue)
        
        return issues
    
    def check_key_strength(self, algorithm: str, bits: int) -> List[SecurityIssue]:
        """Check cryptographic key strength.
        
        Args:
            algorithm: Key algorithm
            bits: Key size in bits
            
        Returns:
            List of issues found
        """
        issues = []
        
        algo_str = str(algorithm).upper()
        
        # RSA minimum 2048 bits
        if 'RSA' in algo_str:
            if bits < 2048:
                issue = SecurityIssue(
                    type=IssueType.KEY_WEAK,
                    severity=Severity.CRITICAL,
                    message=f"RSA key too weak ({bits} bits, minimum 2048 required)",
                    remediation="Generate new RSA key with at least 2048 bits",
                )
                issues.append(issue)
            elif bits < 4096:
                issue = SecurityIssue(
                    type=IssueType.KEY_WEAK,
                    severity=Severity.MEDIUM,
                    message=f"RSA key could be stronger ({bits} bits, 4096 recommended)",
                    remediation="Consider upgrading to 4096-bit RSA or ECDSA",
                )
                issues.append(issue)
        
        # ECDSA P-256 (256 bits) minimum
        elif 'ECDSA' in algo_str:
            if bits < 256:
                issue = SecurityIssue(
                    type=IssueType.KEY_WEAK,
                    severity=Severity.CRITICAL,
                    message=f"ECDSA key too weak ({bits} bits, minimum 256 required)",
                    remediation="Use ECDSA with P-256 or P-384 curve",
                )
                issues.append(issue)
        
        return issues
    
    def check_key_rollover(self, keys: List[KeyInfo]) -> List[SecurityIssue]:
        """Check for proper KSK/ZSK separation and rollover status.
        
        Args:
            keys: List of key information
            
        Returns:
            List of issues found
        """
        issues = []
        
        ksks = [k for k in keys if k.is_ksk]
        zsks = [k for k in keys if k.is_zsk]
        
        if not ksks:
            issue = SecurityIssue(
                type=IssueType.KEY_WEAK,
                severity=Severity.HIGH,
                message="No Key Signing Key (KSK) found",
                remediation="Zone must have at least one KSK for validation",
            )
            issues.append(issue)
        
        if not zsks:
            issue = SecurityIssue(
                type=IssueType.KEY_WEAK,
                severity=Severity.HIGH,
                message="No Zone Signing Key (ZSK) found",
                remediation="Zone must have at least one ZSK for signing records",
            )
            issues.append(issue)
        
        # Check for upcoming key expiration
        now = datetime.utcnow()
        for key in keys:
            if key.valid_until:
                days_until_expiry = (key.valid_until - now).days
                if 0 < days_until_expiry < 30:
                    issue = SecurityIssue(
                        type=IssueType.KEY_ROLLOVER,
                        severity=Severity.MEDIUM,
                        message=f"Key {key.keytag} expires in {days_until_expiry} days",
                        remediation=f"Plan key rollover for key {key.keytag}",
                    )
                    issues.append(issue)
        
        return issues
