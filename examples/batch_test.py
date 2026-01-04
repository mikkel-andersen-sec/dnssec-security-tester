#!/usr/bin/env python3
"""Example: Batch test multiple domains."""

from dnssec_tester import DNSSECTester, DNSSECConfig
from dnssec_tester.reporters.json_reporter import JSONReporter
import json


def main():
    """Test multiple domains."""
    
    domains = [
        'google.com',
        'cloudflare.com',
        'github.com',
        'example.com',
    ]
    
    print(f"Testing {len(domains)} domains...\n")
    
    # Create tester with default config
    config = DNSSECConfig(timeout=10, verbose=False)
    tester = DNSSECTester(config)
    
    # Test all domains
    results = tester.test_domains(domains)
    
    # Print summary
    print("Summary:")
    print("-" * 50)
    for result in results:
        status = result.overall_status.upper()
        issues = len(result.security_issues)
        print(f"{result.domain:30} {status:15} ({issues} issues)")
    
    print("\nStatistics:")
    secure = sum(1 for r in results if r.overall_status == 'secure')
    warnings = sum(1 for r in results if r.overall_status == 'warnings')
    vulnerable = sum(1 for r in results if r.overall_status == 'vulnerable')
    no_dnssec = sum(1 for r in results if r.overall_status == 'no_dnssec')
    
    print(f"  Secure: {secure}")
    print(f"  Warnings: {warnings}")
    print(f"  Vulnerable: {vulnerable}")
    print(f"  No DNSSEC: {no_dnssec}")
    
    # Generate JSON report
    reporter = JSONReporter()
    json_report = reporter.generate(results)
    
    # Save to file
    with open('dnssec_report.json', 'w') as f:
        f.write(json_report)
    print(f"\nReport saved to dnssec_report.json")


if __name__ == '__main__':
    main()
