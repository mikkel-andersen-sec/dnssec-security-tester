"""Main DNSSEC testing module."""

import logging
import time
from datetime import datetime
from typing import List, Optional

from .config import DNSSECConfig, TestMode
from .resolver import DNSResolver
from .validator import DNSSECValidator
from .models import ValidationResult, SecurityIssue, ChainElement, KeyInfo

logger = logging.getLogger(__name__)


class DNSSECTester:
    """Main DNSSEC testing orchestrator."""
    
    def __init__(self, config: Optional[DNSSECConfig] = None):
        """Initialize DNSSEC tester.
        
        Args:
            config: Configuration object (defaults to standard config)
        """
        self.config = config or DNSSECConfig()
        self.resolver = DNSResolver(self.config.nameservers, self.config.timeout)
        self.validator = DNSSECValidator()
        
        if self.config.verbose:
            logging.basicConfig(level=logging.DEBUG)
    
    def test_domain(self, domain: str) -> ValidationResult:
        """Test a domain for DNSSEC security.
        
        Args:
            domain: Domain name to test
            
        Returns:
            ValidationResult with all findings
        """
        start_time = time.time()
        
        logger.info(f"Starting DNSSEC test for {domain}")
        
        # Get DNSKEY records
        dnskeys = self.resolver.get_dnskeys(domain)
        dnssec_enabled = dnskeys is not None
        
        # Initialize result
        result = ValidationResult(
            domain=domain,
            timestamp=datetime.utcnow(),
            dnssec_enabled=dnssec_enabled,
            chain_valid=False,
            validation_time_ms=0.0,
        )
        
        if not dnssec_enabled:
            logger.warning(f"{domain} does not have DNSSEC enabled")
            result.validation_time_ms = (time.time() - start_time) * 1000
            return result
        
        # Parse DNSKEY records
        try:
            keys_list = self._parse_keys(dnskeys)
            result.ksk_list = [k for k in keys_list if k.is_ksk]
            result.zsk_list = [k for k in keys_list if k.is_zsk]
            
            # Run security checks
            if self.config.check_algorithms:
                for key in keys_list:
                    result.security_issues.extend(
                        self.validator.check_algorithm_strength(key.algorithm)
                    )
            
            if self.config.check_key_strength:
                for key in keys_list:
                    result.security_issues.extend(
                        self.validator.check_key_strength(key.algorithm, key.bits)
                    )
            
            # Check key rollover status
            result.security_issues.extend(
                self.validator.check_key_rollover(keys_list)
            )
            
            # Walk the chain if enabled
            if self.config.follow_chain:
                result.chain_of_trust = self._walk_and_validate_chain(domain)
                result.chain_valid = all(elem.valid for elem in result.chain_of_trust)
            
        except Exception as e:
            logger.error(f"Error during validation: {e}")
            issue = SecurityIssue(
                type=__import__('dnssec_tester.models', fromlist=['IssueType']).IssueType.CHAIN_INVALID,
                severity=__import__('dnssec_tester.models', fromlist=['Severity']).Severity.HIGH,
                message=f"Validation error: {str(e)}",
            )
            result.security_issues.append(issue)
        
        result.validation_time_ms = (time.time() - start_time) * 1000
        logger.info(f"DNSSEC test completed for {domain} in {result.validation_time_ms:.2f}ms")
        logger.info(f"Result: {result.overall_status} - {len(result.security_issues)} issues found")
        
        return result
    
    def test_domains(self, domains: List[str]) -> List[ValidationResult]:
        """Test multiple domains.
        
        Args:
            domains: List of domain names
            
        Returns:
            List of validation results
        """
        results = []
        for domain in domains:
            try:
                result = self.test_domain(domain)
                results.append(result)
            except Exception as e:
                logger.error(f"Error testing domain {domain}: {e}")
        return results
    
    def _parse_keys(self, dnskeys) -> List[KeyInfo]:
        """Parse DNSKEY records into KeyInfo objects.
        
        Args:
            dnskeys: DNSKEY RRset
            
        Returns:
            List of KeyInfo objects
        """
        keys = []
        if not dnskeys:
            return keys
        
        for rdata in dnskeys:
            key_info = KeyInfo(
                keytag=dns.dnssec.key_id(rdata),
                algorithm=dns.dnssec.AlgorithmType.to_text(rdata.algorithm),
                bits=rdata.key.bit_length(),
                flags=rdata.flags,
                is_ksk=(rdata.flags & 0x01) != 0,
                is_zsk=True,  # Simplified - ZSK if not KSK
                public_key=rdata.key.hex() if hasattr(rdata, 'key') else None,
            )
            keys.append(key_info)
        
        return keys
    
    def _walk_and_validate_chain(self, domain: str) -> List[ChainElement]:
        """Walk DNSSEC chain and validate each element.
        
        Args:
            domain: Domain to validate
            
        Returns:
            List of chain elements
        """
        chain = []
        
        try:
            chain_data = self.resolver.walk_chain(domain)
            
            for domain_name, data in chain_data:
                element = ChainElement(
                    name=domain_name,
                    rdtype='DNSKEY' if data['dnskeys'] else 'DS',
                    valid=data['dnskeys'] is not None,
                )
                
                if data['dnskeys']:
                    element.keys = self._parse_keys(data['dnskeys'])
                
                chain.append(element)
        
        except Exception as e:
            logger.warning(f"Error walking chain: {e}")
        
        return chain
