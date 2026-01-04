"""Tests for DNSSEC validator."""

import pytest
from dnssec_tester.validator import DNSSECValidator
from dnssec_tester.models import Severity, IssueType


class TestDNSSECValidator:
    """Test DNSSEC validation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = DNSSECValidator()
    
    def test_check_deprecated_algorithms(self):
        """Test detection of deprecated algorithms."""
        issues = self.validator.check_algorithm_strength('RSAMD5')
        assert len(issues) > 0
        assert issues[0].severity == Severity.CRITICAL
    
    def test_check_recommended_algorithms(self):
        """Test that recommended algorithms pass."""
        issues = self.validator.check_algorithm_strength('ECDSAP256SHA256')
        # Should have no critical issues
        critical = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(critical) == 0
    
    def test_check_rsa_key_strength(self):
        """Test RSA key strength validation."""
        # Test weak key
        issues = self.validator.check_key_strength('RSASHA256', 1024)
        assert len(issues) > 0
        assert issues[0].severity == Severity.CRITICAL
        
        # Test adequate key
        issues = self.validator.check_key_strength('RSASHA256', 2048)
        assert len(issues) == 0 or all(i.severity != Severity.CRITICAL for i in issues)
    
    def test_check_ecdsa_key_strength(self):
        """Test ECDSA key strength validation."""
        # Test P-256 key (256 bits)
        issues = self.validator.check_key_strength('ECDSAP256SHA256', 256)
        assert len(issues) == 0 or all(i.severity != Severity.CRITICAL for i in issues)
