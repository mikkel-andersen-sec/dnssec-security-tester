"""Tests for main DNSSEC tester."""

import pytest
from dnssec_tester import DNSSECTester, DNSSECConfig
from dnssec_tester.config import TestMode


class TestDNSSECTester:
    """Test main DNSSEC testing functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        config = DNSSECConfig(
            timeout=5,
            mode=TestMode.FAST,
            verbose=False,
        )
        self.tester = DNSSECTester(config)
    
    def test_tester_initialization(self):
        """Test tester initialization."""
        assert self.tester is not None
        assert self.tester.config is not None
    
    @pytest.mark.skipif(True, reason="Requires external DNS query")
    def test_test_domain(self):
        """Test domain validation."""
        result = self.tester.test_domain('example.com')
        assert result is not None
        assert result.domain == 'example.com'
        assert hasattr(result, 'dnssec_enabled')
        assert hasattr(result, 'security_issues')
