# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-01-04

### Added

**Core DNSSEC Validation**
- Initial DNSSEC validation engine with signature verification
- Chain of trust validation with root to domain walking
- DNSKEY and DS record parsing
- RRSIG signature expiration checking

**Security Analysis**
- RFC 8624 algorithm compliance checking
- Cryptographic key strength validation (RSA, ECDSA, Ed25519)
- KSK/ZSK separation verification
- Key rollover status detection
- Signature expiration warnings

**Command Line Interface**
- Single domain testing: `dnssec-tester test <domain>`
- Batch domain testing: `dnssec-tester batch <file>`
- Multiple output formats: JSON, CSV, HTML, text
- Configurable nameservers and timeouts
- Verbose logging support

**Reporting**
- JSON report generation
- CSV report generation
- HTML report generation
- Plain text report generation
- Detailed security issue reporting with severity levels
- Summary statistics

**Python API**
- `DNSSECTester` class for programmatic access
- `DNSSECConfig` for configuration management
- `ValidationResult` data model
- `SecurityIssue` for issue tracking

**Documentation**
- Comprehensive README with features and examples
- Installation instructions
- Quick start guide
- Architecture documentation
- Security references

### Known Limitations

- Chain validation follows only parent delegations (not all possible chains)
- No NSEC/NSEC3 enumeration analysis in v0.1
- No historical signature validation
- No DANE support
- Limited to synchronous DNS queries

## [Unreleased]

### Planned Features

- [ ] NSEC/NSEC3 enumeration analysis
- [ ] Historical signature validation
- [ ] DANE protocol support
- [ ] Async DNS queries for performance
- [ ] DNS CAA record analysis
- [ ] Web UI dashboard
- [ ] API server mode
- [ ] Database storage for historical results
- [ ] Monitoring/alerting integrations
- [ ] Custom policy definitions
- [ ] Automated remediation suggestions
