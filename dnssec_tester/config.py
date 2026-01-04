"""Configuration management for DNSSEC Tester."""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
import os


class TestMode(Enum):
    """Testing modes with different levels of analysis."""
    FAST = "fast"  # Basic validation only
    COMPREHENSIVE = "comprehensive"  # Full chain validation
    DEEP = "deep"  # All checks including best practices


class ReportFormat(Enum):
    """Output report formats."""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    TEXT = "text"
    PLAINTEXT = "text"


@dataclass
class DNSSECConfig:
    """Configuration for DNSSEC testing."""
    
    # Query settings
    timeout: int = 10
    nameservers: List[str] = field(default_factory=lambda: ['8.8.8.8', '1.1.1.1'])
    use_dnssec: bool = True
    follow_chain: bool = True
    
    # Testing mode
    mode: TestMode = TestMode.COMPREHENSIVE
    
    # Validation settings
    validate_chain: bool = True
    check_expiration: bool = True
    check_algorithms: bool = True
    check_key_strength: bool = True
    
    # Output settings
    verbose: bool = False
    debug: bool = False
    
    # Reporting
    report_format: ReportFormat = ReportFormat.JSON
    include_chain: bool = True
    include_keys: bool = True
    include_signatures: bool = False
    
    # Performance
    parallel_queries: int = 3
    cache_results: bool = True
    
    @classmethod
    def from_env(cls) -> 'DNSSECConfig':
        """Create configuration from environment variables."""
        return cls(
            timeout=int(os.getenv('DNSSEC_TIMEOUT', '10')),
            use_dnssec=os.getenv('DNSSEC_USE_DNSSEC', 'true').lower() == 'true',
            follow_chain=os.getenv('DNSSEC_FOLLOW_CHAIN', 'true').lower() == 'true',
            verbose=os.getenv('DNSSEC_VERBOSE', 'false').lower() == 'true',
            debug=os.getenv('DNSSEC_DEBUG', 'false').lower() == 'true',
        )
