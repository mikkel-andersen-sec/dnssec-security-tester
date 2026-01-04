"""Data models for DNSSEC validation results."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """Security issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueType(Enum):
    """Types of security issues."""
    CHAIN_INVALID = "chain_invalid"
    SIGNATURE_EXPIRED = "signature_expired"
    ALGORITHM_WEAK = "algorithm_weak"
    KEY_WEAK = "key_weak"
    DS_MISMATCH = "ds_mismatch"
    EXPIRATION_WARNING = "expiration_warning"
    CONFIGURATION_ISSUE = "configuration_issue"
    KEY_ROLLOVER = "key_rollover"
    NSEC_ISSUE = "nsec_issue"
    TRUST_ANCHOR_ISSUE = "trust_anchor_issue"


@dataclass
class SecurityIssue:
    """Represents a security issue found during validation."""
    type: IssueType
    severity: Severity
    message: str
    details: Optional[str] = None
    remediation: Optional[str] = None
    affected_rrset: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class KeyInfo:
    """Information about a DNSSEC key."""
    keytag: int
    algorithm: str
    bits: int
    flags: int
    is_ksk: bool  # Key Signing Key
    is_zsk: bool  # Zone Signing Key
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    public_key: Optional[str] = None


@dataclass
class ChainElement:
    """Represents a single element in the DNSSEC validation chain."""
    name: str
    rdtype: str  # Record type (DNSKEY, DS, etc.)
    valid: bool
    keys: List[KeyInfo] = field(default_factory=list)
    signatures: List[str] = field(default_factory=list)
    issues: List[SecurityIssue] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Complete DNSSEC validation result for a domain."""
    domain: str
    timestamp: datetime
    dnssec_enabled: bool
    chain_valid: bool
    validation_time_ms: float
    
    # Chain information
    chain_of_trust: List[ChainElement] = field(default_factory=list)
    
    # Key information
    ksk_list: List[KeyInfo] = field(default_factory=list)
    zsk_list: List[KeyInfo] = field(default_factory=list)
    
    # Issues found
    security_issues: List[SecurityIssue] = field(default_factory=list)
    
    # Statistics
    total_rrsets_signed: int = 0
    expired_signatures: int = 0
    warnings: int = 0
    
    # Additional info
    nameservers: List[str] = field(default_factory=list)
    resolver_used: Optional[str] = None
    
    @property
    def overall_status(self) -> str:
        """Get overall security status."""
        if not self.dnssec_enabled:
            return "no_dnssec"
        if any(i.severity == Severity.CRITICAL for i in self.security_issues):
            return "critical_issues"
        if any(i.severity == Severity.HIGH for i in self.security_issues):
            return "vulnerable"
        if self.security_issues:
            return "warnings"
        return "secure"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return {
            'domain': self.domain,
            'timestamp': self.timestamp.isoformat(),
            'dnssec_enabled': self.dnssec_enabled,
            'chain_valid': self.chain_valid,
            'overall_status': self.overall_status,
            'validation_time_ms': self.validation_time_ms,
            'chain_of_trust': [
                {
                    'name': elem.name,
                    'rdtype': elem.rdtype,
                    'valid': elem.valid,
                    'keys': [
                        {
                            'keytag': k.keytag,
                            'algorithm': k.algorithm,
                            'bits': k.bits,
                            'is_ksk': k.is_ksk,
                            'is_zsk': k.is_zsk,
                            'valid_until': k.valid_until.isoformat() if k.valid_until else None,
                        }
                        for k in elem.keys
                    ],
                }
                for elem in self.chain_of_trust
            ],
            'security_issues': [
                {
                    'type': issue.type.value,
                    'severity': issue.severity.value,
                    'message': issue.message,
                    'details': issue.details,
                    'remediation': issue.remediation,
                }
                for issue in self.security_issues
            ],
        }
