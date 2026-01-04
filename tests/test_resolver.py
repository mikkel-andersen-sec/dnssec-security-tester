"""Tests for DNS resolver."""

import pytest
from dnssec_tester.resolver import DNSResolver


class TestDNSResolver:
    """Test DNS resolver functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.resolver = DNSResolver(['8.8.8.8', '1.1.1.1'], timeout=5)
    
    def test_resolver_initialization(self):
        """Test resolver initialization."""
        assert self.resolver is not None
        assert self.resolver.timeout == 5
    
    @pytest.mark.skipif(True, reason="Requires external DNS query")
    def test_query_dnskey(self):
        """Test DNSKEY query."""
        result = self.resolver.get_dnskeys('example.com')
        assert result is not None
    
    @pytest.mark.skipif(True, reason="Requires external DNS query")
    def test_query_ds(self):
        """Test DS query."""
        result = self.resolver.get_ds_records('example.com')
        # DS records may or may not exist, just test no exception
        assert True
