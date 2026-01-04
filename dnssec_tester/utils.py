"""Utility functions for DNSSEC Tester."""

import logging
import dns.name
import dns.rdatatype
from typing import Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


def is_valid_domain(domain: str) -> bool:
    """Check if domain name is valid.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        dns.name.from_text(domain)
        return True
    except Exception:
        return False


def normalize_domain(domain: str) -> str:
    """Normalize domain name.
    
    Args:
        domain: Domain name
        
    Returns:
        Normalized domain name
    """
    domain = domain.lower().strip()
    if not domain.endswith('.'):
        domain += '.'
    return domain


def get_parent_domain(domain: str) -> Optional[str]:
    """Get parent domain.
    
    Args:
        domain: Domain name
        
    Returns:
        Parent domain or None for root
    """
    try:
        name = dns.name.from_text(domain)
        if name == dns.name.root:
            return None
        return str(name.parent())
    except Exception:
        return None


def get_tld(domain: str) -> Optional[str]:
    """Get top-level domain.
    
    Args:
        domain: Domain name
        
    Returns:
        TLD (e.g., 'com', 'org')
    """
    try:
        name = dns.name.from_text(domain)
        # Typically the parent of root is the TLD
        labels = name.labels
        if len(labels) >= 1:
            return labels[-2].decode() if len(labels) > 1 else labels[0].decode()
    except Exception:
        pass
    return None


def format_timestamp(dt: datetime) -> str:
    """Format datetime for display.
    
    Args:
        dt: Datetime object
        
    Returns:
        Formatted timestamp string
    """
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')


def get_algorithm_name(algo_num: int) -> str:
    """Get DNSSEC algorithm name from number.
    
    Args:
        algo_num: Algorithm number
        
    Returns:
        Algorithm name
    """
    algorithms = {
        1: 'RSAMD5',
        3: 'DSA',
        5: 'RSASHA1',
        6: 'DSA-NSEC3-SHA1',
        7: 'RSASHA1-NSEC3-SHA1',
        8: 'RSASHA256',
        10: 'RSASHA512',
        12: 'ECC-GOST',
        13: 'ECDSAP256SHA256',
        14: 'ECDSAP384SHA384',
        15: 'ED25519',
        16: 'ED448',
    }
    return algorithms.get(algo_num, f'UNKNOWN({algo_num})')


def get_digest_name(digest_type: int) -> str:
    """Get digest algorithm name.
    
    Args:
        digest_type: Digest type number
        
    Returns:
        Digest name
    """
    digests = {
        1: 'SHA-1',
        2: 'SHA-256',
        3: 'GOST R 34.11-94',
        4: 'SHA-384',
        5: 'SHA-512',
    }
    return digests.get(digest_type, f'UNKNOWN({digest_type})')


def parse_rrsig_expiration(rrsig) -> Optional[datetime]:
    """Parse RRSIG expiration time.
    
    Args:
        rrsig: RRSIG record
        
    Returns:
        Expiration datetime or None
    """
    try:
        if hasattr(rrsig, 'expiration'):
            return datetime.utcfromtimestamp(rrsig.expiration)
    except Exception:
        pass
    return None


def parse_rrsig_inception(rrsig) -> Optional[datetime]:
    """Parse RRSIG inception time.
    
    Args:
        rrsig: RRSIG record
        
    Returns:
        Inception datetime or None
    """
    try:
        if hasattr(rrsig, 'inception'):
            return datetime.utcfromtimestamp(rrsig.inception)
    except Exception:
        pass
    return None


def days_until_expiration(dt: Optional[datetime]) -> Optional[int]:
    """Calculate days until expiration.
    
    Args:
        dt: Expiration datetime
        
    Returns:
        Days until expiration (negative if expired)
    """
    if not dt:
        return None
    return (dt - datetime.utcnow()).days


def is_dnssec_enabled(dnskeys) -> bool:
    """Check if DNSSEC is enabled (DNSKEY records exist).
    
    Args:
        dnskeys: DNSKEY RRset or None
        
    Returns:
        True if DNSSEC is enabled
    """
    return dnskeys is not None and len(dnskeys) > 0
