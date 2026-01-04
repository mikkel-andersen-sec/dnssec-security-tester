"""Security analysis module for DNSSEC."""

import logging
from typing import List, Dict, Any
from .models import SecurityIssue, Severity, IssueType, ValidationResult

logger = logging.getLogger(__name__)


class DNSSECAnalyzer:
    """Analyzes DNSSEC validation results for security issues."""
    
    def __init__(self):
        """Initialize analyzer."""
        self.issues: List[SecurityIssue] = []
    
    def analyze_result(self, result: ValidationResult) -> List[SecurityIssue]:
        """Analyze validation result for security issues.
        
        Args:
            result: ValidationResult from DNSSECTester
            
        Returns:
            List of additional security issues found
        """
        issues = []
        
        # Check if DNSSEC is enabled
        if not result.dnssec_enabled:
            issue = SecurityIssue(
                type=IssueType.CONFIGURATION_ISSUE,
                severity=Severity.HIGH,
                message="DNSSEC is not enabled for this domain",
                remediation="Enable DNSSEC on the authoritative nameserver",
            )
            issues.append(issue)
            return issues
        
        # Check chain validity
        if not result.chain_valid:
            issue = SecurityIssue(
                type=IssueType.CHAIN_INVALID,
                severity=Severity.CRITICAL,
                message="DNSSEC chain of trust validation failed",
                remediation="Check DNSSEC configuration and signatures",
            )
            issues.append(issue)
        
        # Check for missing KSK/ZSK
        if not result.ksk_list:
            issue = SecurityIssue(
                type=IssueType.KEY_WEAK,
                severity=Severity.HIGH,
                message="No Key Signing Key (KSK) found",
                remediation="Add a KSK to the zone",
            )
            issues.append(issue)
        
        if not result.zsk_list:
            issue = SecurityIssue(
                type=IssueType.KEY_WEAK,
                severity=Severity.HIGH,
                message="No Zone Signing Key (ZSK) found",
                remediation="Add a ZSK to the zone",
            )
            issues.append(issue)
        
        # Analyze key material
        all_keys = result.ksk_list + result.zsk_list
        if all_keys:
            issues.extend(self._analyze_keys(all_keys))
        
        # Analyze chain of trust
        if result.chain_of_trust:
            issues.extend(self._analyze_chain(result.chain_of_trust))
        
        return issues
    
    def _analyze_keys(self, keys) -> List[SecurityIssue]:
        """Analyze key material.
        
        Args:
            keys: List of KeyInfo objects
            
        Returns:
            List of security issues
        """
        issues = []
        
        # Check key counts
        ksk_count = sum(1 for k in keys if k.is_ksk)
        zsk_count = sum(1 for k in keys if k.is_zsk)
        
        # Recommend multiple KSKs
        if ksk_count == 1:
            issue = SecurityIssue(
                type=IssueType.CONFIGURATION_ISSUE,
                severity=Severity.MEDIUM,
                message="Only one KSK found; redundancy recommended",
                remediation="Consider adding a second KSK for key rollover scenarios",
            )
            issues.append(issue)
        
        return issues
    
    def _analyze_chain(self, chain) -> List[SecurityIssue]:
        """Analyze chain of trust.
        
        Args:
            chain: List of ChainElement objects
            
        Returns:
            List of security issues
        """
        issues = []
        
        # Check for gaps in chain
        for element in chain:
            if not element.valid:
                issue = SecurityIssue(
                    type=IssueType.CHAIN_INVALID,
                    severity=Severity.HIGH,
                    message=f"Chain element {element.name} validation failed",
                    remediation=f"Check DNSSEC configuration for {element.name}",
                )
                issues.append(issue)
        
        return issues
    
    def generate_recommendations(self, result: ValidationResult) -> List[str]:
        """Generate security recommendations.
        
        Args:
            result: ValidationResult
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if not result.dnssec_enabled:
            recommendations.append(
                "Enable DNSSEC to protect against DNS spoofing and cache poisoning"
            )
        
        if result.security_issues:
            critical_issues = [i for i in result.security_issues if i.severity == Severity.CRITICAL]
            if critical_issues:
                recommendations.append(
                    f"Address {len(critical_issues)} critical security issues immediately"
                )
        
        # Key rollover planning
        if result.ksk_list or result.zsk_list:
            recommendations.append(
                "Plan for periodic key rollover every 1-2 years"
            )
        
        # Monitoring
        recommendations.append(
            "Monitor DNSSEC validation status regularly using this tool"
        )
        
        return recommendations
