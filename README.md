# DNSSEC Security Tester

A comprehensive Python tool for testing and validating DNSSEC implementation, identifying security vulnerabilities, and assessing the integrity of DNS records through cryptographic chain of trust validation.

## Features

### Core DNSSEC Validation
- **Chain of Trust Validation**: Verifies the complete DNSSEC validation path from root to domain
- **Signature Verification**: Validates RRSIG (DNSSEC signature) authenticity against DNSKEY records
- **Key Strength Analysis**: Evaluates cryptographic algorithm strength (RSA, ECDSA, Ed25519)
- **DS Record Validation**: Checks Delegation Signer records for proper parent zone linkage

### Security Assessment
- **Zone Configuration Audit**: Identifies DNSSEC misconfigurations and deployment gaps
- **Key Rollover Detection**: Monitors KSK/ZSK (Key Signing Key / Zone Signing Key) status and validity periods
- **Signature Expiration Analysis**: Warns about soon-to-expire signatures
- **NSEC/NSEC3 Verification**: Validates negative assertion records and zone enumeration protections
- **Algorithm Policy Compliance**: Checks against RFC 8624 recommended and deprecated algorithms

### Reporting & Visualization
- **Detailed Security Reports**: JSON, CSV, and plaintext output formats
- **Chain Visualization**: ASCII representation of the validation chain
- **Multi-domain Batch Testing**: Scan multiple domains with consolidated reporting
- **Performance Metrics**: Query timing and resolver information

## Installation

### Requirements
- Python 3.8+
- dnspython >= 2.4.0
- cryptography >= 40.0.0
- click >= 8.0.0 (for CLI)
- tabulate >= 0.9.0 (for formatted output)

### Setup

```bash
# Clone the repository
git clone https://github.com/mikkel-andersen-sec/dnssec-security-tester.git
cd dnssec-security-tester

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Command Line Usage

```bash
# Test a single domain
python -m dnssec_tester test example.com

# Test with detailed output
python -m dnssec_tester test example.com --verbose

# Test multiple domains from file
python -m dnssec_tester batch domains.txt --output results.json

# Generate HTML report
python -m dnssec_tester test example.com --report html --output report.html

# Check only specific record types
python -m dnssec_tester test example.com --rtype A,MX,NS
```

### Python API Usage

```python
from dnssec_tester import DNSSECTester
from dnssec_tester.config import DNSSECConfig

# Configure tester
config = DNSSECConfig(
    timeout=10,
    use_dnssec=True,
    follow_chain=True,
    verbose=True
)

# Create tester instance
tester = DNSSECTester(config)

# Test domain
results = tester.test_domain('example.com')

# Print results
print(f"Domain: {results.domain}")
print(f"DNSSEC Enabled: {results.dnssec_enabled}")
print(f"Chain Valid: {results.chain_valid}")
print(f"Issues Found: {len(results.security_issues)}")

for issue in results.security_issues:
    print(f"  - [{issue.severity}] {issue.message}")
```

## Architecture

```
dnssec_tester/
├── __init__.py
├── cli.py                 # Command-line interface
├── tester.py             # Core DNSSEC testing logic
├── validator.py          # DNSSEC validation engine
├── resolver.py           # DNS query and chain walking
├── analyzer.py           # Security analysis module
├── config.py             # Configuration management
├── models.py             # Data structures for results
├── reporters/            # Output format handlers
│   ├── __init__.py
│   ├── json_reporter.py
│   ├── html_reporter.py
│   ├── csv_reporter.py
│   └── text_reporter.py
└── utils.py              # Helper functions

tests/
├── test_validator.py
├── test_resolver.py
├── test_analyzer.py
└── fixtures/             # Test data and zone files
```

## Testing Modes

### Fast Mode (Default)
- Basic DNSSEC validation
- Key algorithm verification
- Signature expiration checks
- ~100-200ms per domain

### Comprehensive Mode
- Full chain of trust validation
- Algorithm policy analysis
- NSEC/NSEC3 enumeration analysis
- Key material verification
- ~500ms-2s per domain

### Deep Analysis Mode
- All comprehensive checks
- Historical signature verification
- Parent-child delegation analysis
- Configuration best practice audit
- ~2-5s per domain

## Security Checks

The tool performs the following security validations:

| Check | Description | Severity |
|-------|-------------|----------|
| **Chain Validity** | Complete path from root to domain validates | Critical |
| **Signature Expiration** | RRSIG records not expired or soon-to-expire | High |
| **Algorithm Strength** | Cryptographic algorithms meet RFC 8624 standards | High |
| **Key Strength** | RSA keys ≥2048 bits, ECDSA curves appropriate | High |
| **DS Match** | Delegation Signer records hash KSK correctly | Critical |
| **KSK/ZSK Separation** | Proper separation of signing keys | Medium |
| **NSEC3 Parameters** | NSEC3 iteration count appropriate | Medium |
| **Trust Anchor** | Root trust anchor is valid and up-to-date | Critical |

## Output Examples

### Text Report
```
DNSSEC Validation Report: example.com
=====================================

Overall Status: ✓ SECURE
Validation Time: 245ms

Chain of Trust:
  . (Root)
    ↓ [Valid DS] [Valid DNSKEY]
  com. (TLD)
    ↓ [Valid DS] [Valid DNSKEY]
  example.com. (Zone)
    ↓ [Valid RRSIG] [All RRsets signed]

Key Information:
  KSK (Key 12345):
    - Algorithm: ECDSAP256SHA256
    - Bits: 256
    - Valid Until: 2026-01-10
    
  ZSK (Key 67890):
    - Algorithm: ECDSAP256SHA256
    - Bits: 256
    - Valid Until: 2025-07-15

Security Issues: None detected
```

### JSON Report
```json
{
  "domain": "example.com",
  "timestamp": "2026-01-04T15:30:00Z",
  "overall_status": "secure",
  "dnssec_enabled": true,
  "chain_valid": true,
  "validation_time_ms": 245,
  "chain_of_trust": [
    {
      "name": ".",
      "type": "root",
      "valid": true
    },
    {
      "name": "com.",
      "type": "tld",
      "valid": true
    },
    {
      "name": "example.com.",
      "type": "zone",
      "valid": true
    }
  ],
  "security_issues": []
}
```

## Configuration

### Environment Variables
```bash
export DNSSEC_TIMEOUT=15
export DNSSEC_NAMESERVER=8.8.8.8
export DNSSEC_VERBOSE=true
export DNSSEC_FOLLOW_CHAIN=true
```

### Config File (dnssec.conf)
```ini
[dnssec]
timeout = 10
follow_chain = true
validate_chain = true
check_expiration = true

[nameservers]
primary = 8.8.8.8
secondary = 1.1.1.1

[reporting]
format = json
include_chain = true
include_keys = true
```

## Examples

### Test Google's DNS
```bash
python -m dnssec_tester test google.com --verbose
```

### Batch Test Multiple Domains
```bash
cat > domains.txt << EOF
example.com
google.com
github.com
cloudflare.com
EOF

python -m dnssec_tester batch domains.txt --output results.json --report json
```

### Check Specific Record Types
```bash
python -m dnssec_tester test example.com --rtype A --rtype MX --rtype NS
```

### Monitor DNSSEC Status Over Time
```bash
python -m dnssec_tester test example.com --output daily_$(date +%Y%m%d).json
```

## References

- [RFC 4034](https://tools.ietf.org/html/rfc4034) - DNSSEC Protocol Mechanisms
- [RFC 4035](https://tools.ietf.org/html/rfc4035) - DNSSEC Protocol Specification
- [RFC 5910](https://tools.ietf.org/html/rfc5910) - Domain Name System (DNS) DNSSEC Key and Signing Policy
- [RFC 8624](https://tools.ietf.org/html/rfc8624) - DNSSEC Algorithm Implementation Status
- [DNSSEC.net](https://dnssec.net) - DNSSEC Information and Resources
- [DNSViz](https://dnsviz.net/) - DNSSEC Visualization and Analysis
- [dnspython Documentation](https://www.dnspython.org/)

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes with clear messages
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

## License

MIT License - See LICENSE file for details

## Author

**Mikkel Andersen** - Senior Security Researcher
- GitHub: [@mikkel-andersen-sec](https://github.com/mikkel-andersen-sec)
- Company: Sentinel Cybersecurity, Copenhagen

## Disclaimer

This tool is designed for educational and authorized security testing purposes only. Unauthorized testing of DNS infrastructure may be illegal. Always obtain proper authorization before testing systems you don't own or have explicit permission to test.

## Changelog

### v0.1.0 (2026-01-04)
- Initial release
- Core DNSSEC validation functionality
- CLI interface with multiple output formats
- Security assessment engine
- Support for single domain and batch testing
