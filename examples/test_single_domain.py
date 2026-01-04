#!/usr/bin/env python3
"""Example: Test a single domain for DNSSEC."""

from dnssec_tester import DNSSECTester, DNSSECConfig
from dnssec_tester.config import TestMode
import json


def main():
    """Test example.com for DNSSEC security."""
    
    # Create configuration
    config = DNSSECConfig(
        timeout=10,
        mode=TestMode.COMPREHENSIVE,
        verbose=True,
        follow_chain=True,
        check_algorithms=True,
        check_key_strength=True,
    )
    
    # Create tester
    tester = DNSSECTester(config)
    
    # Test domain
    print("Testing example.com...")
    result = tester.test_domain('example.com')
    
    # Print results
    print(f"\nDomain: {result.domain}")
    print(f"Status: {result.overall_status}")
    print(f"DNSSEC Enabled: {result.dnssec_enabled}")
    print(f"Chain Valid: {result.chain_valid}")
    print(f"Validation Time: {result.validation_time_ms:.2f}ms")
    
    if result.ksk_list:
        print(f"\nKey Signing Keys: {len(result.ksk_list)}")
        for key in result.ksk_list:
            print(f"  - Tag {key.keytag}: {key.algorithm} ({key.bits} bits)")
    
    if result.zsk_list:
        print(f"\nZone Signing Keys: {len(result.zsk_list)}")
        for key in result.zsk_list:
            print(f"  - Tag {key.keytag}: {key.algorithm} ({key.bits} bits)")
    
    if result.security_issues:
        print(f"\nSecurity Issues: {len(result.security_issues)}")
        for issue in result.security_issues:
            print(f"  [{issue.severity.value.upper()}] {issue.message}")
            if issue.remediation:
                print(f"    → {issue.remediation}")
    else:
        print("\nNo security issues found!")
    
    # Output as JSON
    print(f"\nJSON Output:\n{json.dumps(result.to_dict(), indent=2)}")


if __name__ == '__main__':
    main()
