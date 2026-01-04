"""DNS resolver with DNSSEC support."""

import dns.resolver
import dns.query
import dns.name
import dns.rdatatype
import dns.dnssec
from typing import Optional, List, Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)


class DNSResolver:
    """DNS resolver with DNSSEC chain walking capabilities."""
    
    def __init__(self, nameservers: List[str], timeout: int = 10):
        """Initialize resolver.
        
        Args:
            nameservers: List of nameserver IPs to use
            timeout: Query timeout in seconds
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
        self.timeout = timeout
    
    def query(self, domain: str, rdtype: str, dnssec: bool = True) -> Optional[dns.rrset.RRset]:
        """Query DNS record with optional DNSSEC.
        
        Args:
            domain: Domain name to query
            rdtype: Record type (A, AAAA, MX, NS, DNSKEY, DS, etc.)
            dnssec: Enable DNSSEC flags
            
        Returns:
            DNS RRset or None if query fails
        """
        try:
            if dnssec:
                self.resolver.use_dnssec = True
            
            domain_name = dns.name.from_text(domain)
            rdtype_val = dns.rdatatype.from_text(rdtype)
            
            response = self.resolver.resolve(domain_name, rdtype_val)
            return response.response.answer[0] if response.response.answer else None
        except Exception as e:
            logger.debug(f"Query failed for {domain} {rdtype}: {e}")
            return None
    
    def get_dnskeys(self, domain: str) -> Optional[dns.rrset.RRset]:
        """Get DNSKEY records for a domain."""
        return self.query(domain, 'DNSKEY')
    
    def get_ds_records(self, domain: str) -> Optional[dns.rrset.RRset]:
        """Get DS records for a domain."""
        return self.query(domain, 'DS')
    
    def get_rrsigs(self, domain: str, rdtype: str) -> Optional[dns.rrset.RRset]:
        """Get RRSIG records for a domain and record type."""
        try:
            domain_name = dns.name.from_text(domain)
            rdtype_val = dns.rdatatype.from_text(rdtype)
            
            response = self.resolver.resolve(domain_name, rdtype_val)
            
            # Extract RRSIG records from response
            for rrset in response.response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    return rrset
            return None
        except Exception as e:
            logger.debug(f"RRSIG query failed for {domain} {rdtype}: {e}")
            return None
    
    def walk_chain(self, domain: str) -> List[Tuple[str, Dict[str, Any]]]:
        """Walk the DNSSEC chain from root to domain.
        
        Returns:
            List of tuples (domain_name, chain_data)
        """
        chain = []
        current = dns.name.from_text(domain)
        
        while current != dns.name.root:
            try:
                dnskeys = self.get_dnskeys(str(current))
                ds_records = self.get_ds_records(str(current))
                
                chain.append((
                    str(current),
                    {
                        'dnskeys': dnskeys,
                        'ds_records': ds_records,
                    }
                ))
                
                # Move to parent domain
                current = current.parent()
            except Exception as e:
                logger.debug(f"Error walking chain for {current}: {e}")
                break
        
        return chain
