"""DNSSEC Security Tester - Comprehensive DNSSEC validation and security analysis tool."""

__version__ = '0.1.0'
__author__ = 'Mikkel Andersen'
__email__ = 'mikkel.andersen@sentinelcybersecurity.com'
__url__ = 'https://github.com/mikkel-andersen-sec/dnssec-security-tester'

from .tester import DNSSECTester
from .config import DNSSECConfig
from .models import (
    ValidationResult,
    SecurityIssue,
    KeyInfo,
    ChainElement,
)

__all__ = [
    'DNSSECTester',
    'DNSSECConfig',
    'ValidationResult',
    'SecurityIssue',
    'KeyInfo',
    'ChainElement',
]
