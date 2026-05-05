"""
Validation Utilities for Threat Indicators
Ensures data quality and format correctness
"""

import re
import ipaddress
from typing import Union, Optional, Tuple, List
from urllib.parse import urlparse

# Regular expressions for validation
IPV4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
IPV6_PATTERN = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
URL_PATTERN = re.compile(
    r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*/?.*$'
)
MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
CIDR_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


def validate_ip(ip_string: str) -> bool:
    """
    Validate IPv4 or IPv6 address
    
    Args:
        ip_string: IP address to validate
    
    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def validate_ipv4(ip_string: str) -> bool:
    """
    Validate IPv4 address specifically
    
    Args:
        ip_string: IPv4 address to validate
    
    Returns:
        True if valid IPv4 address
    """
    if not IPV4_PATTERN.match(ip_string):
        return False
    
    try:
        parts = ip_string.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def validate_ipv6(ip_string: str) -> bool:
    """
    Validate IPv6 address specifically
    
    Args:
        ip_string: IPv6 address to validate
    
    Returns:
        True if valid IPv6 address
    """
    try:
        ipaddress.IPv6Address(ip_string)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """
    Validate domain name
    
    Args:
        domain: Domain name to validate
    
    Returns:
        True if valid domain name
    """
    if not domain or len(domain) > 253:
        return False
    
    # Check for valid characters
    if not DOMAIN_PATTERN.match(domain):
        return False
    
    # Check each label
    labels = domain.split('.')
    for label in labels:
        if len(label) > 63 or len(label) < 1:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
    
    return True


def validate_url(url: str, require_scheme: bool = True) -> bool:
    """
    Validate URL
    
    Args:
        url: URL to validate
        require_scheme: Require http:// or https:// scheme
    
    Returns:
        True if valid URL
    """
    if not url:
        return False
    
    if require_scheme:
        if not url.startswith(('http://', 'https://')):
            return False
    
    try:
        parsed = urlparse(url)
        
        # Check for valid scheme
        if require_scheme and parsed.scheme not in ('http', 'https'):
            return False
        
        # Check for valid netloc (domain or IP)
        if parsed.netloc:
            netloc = parsed.netloc.split(':')[0]  # Remove port
            if not (validate_domain(netloc) or validate_ip(netloc)):
                return False
        else:
            return False
        
        return True
        
    except Exception:
        return False


def validate_hash(hash_string: str, hash_type: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate cryptographic hash (MD5, SHA1, SHA256)
    
    Args:
        hash_string: Hash to validate
        hash_type: Optional specific hash type to check
    
    Returns:
        Tuple of (is_valid, detected_type)
    """
    if not hash_string:
        return False, None
    
    # Check MD5
    if MD5_PATTERN.match(hash_string):
        if hash_type is None or hash_type.lower() == 'md5':
            return True, 'md5'
    
    # Check SHA1
    if SHA1_PATTERN.match(hash_string):
        if hash_type is None or hash_type.lower() == 'sha1':
            return True, 'sha1'
    
    # Check SHA256
    if SHA256_PATTERN.match(hash_string):
        if hash_type is None or hash_type.lower() == 'sha256':
            return True, 'sha256'
    
    return False, None


def validate_cidr(cidr_string: str) -> bool:
    """
    Validate CIDR notation (e.g., 192.168.1.0/24)
    
    Args:
        cidr_string: CIDR notation to validate
    
    Returns:
        True if valid CIDR notation
    """
    if not CIDR_PATTERN.match(cidr_string):
        return False
    
    try:
        network = ipaddress.ip_network(cidr_string, strict=False)
        
        # Check if the network is valid (not host bits set)
        if cidr_string != str(network):
            # Host bits are set, but it's still a valid network
            pass
        
        return True
    except ValueError:
        return False


def validate_email(email: str) -> bool:
    """
    Validate email address
    
    Args:
        email: Email address to validate
    
    Returns:
        True if valid email format
    """
    if not email:
        return False
    
    return bool(EMAIL_PATTERN.match(email))


def validate_port(port: Union[int, str]) -> bool:
    """
    Validate network port number
    
    Args:
        port: Port number to validate
    
    Returns:
        True if valid port (1-65535)
    """
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def validate_indicator_type(indicator: str) -> str:
    """
    Automatically detect indicator type
    
    Args:
        indicator: Raw indicator string
    
    Returns:
        Detected type: 'ip', 'domain', 'url', 'hash', 'cidr', 'email', 'unknown'
    """
    if not indicator:
        return 'unknown'
    
    indicator = indicator.strip().lower()
    
    # Check IP
    if validate_ip(indicator):
        return 'ip'
    
    # Check CIDR
    if validate_cidr(indicator):
        return 'cidr'
    
    # Check URL
    if validate_url(indicator, require_scheme=False):
        return 'url'
    
    # Check hash
    is_hash, hash_type = validate_hash(indicator)
    if is_hash:
        return 'hash'
    
    # Check domain
    if validate_domain(indicator):
        return 'domain'
    
    # Check email
    if validate_email(indicator):
        return 'email'
    
    return 'unknown'


def sanitize_indicator(indicator: str) -> str:
    """
    Sanitize indicator by removing harmful characters
    """
    if not indicator:
        return ""
    
    # Remove whitespace
    indicator = indicator.strip()
    
    # Remove newlines and carriage returns
    indicator = indicator.replace('\n', '').replace('\r', '')
    
    # Remove null bytes
    indicator = indicator.replace('\x00', '')
    
    # Limit length
    if len(indicator) > 255:
        indicator = indicator[:255]
    
    return indicator


class ThreatValidator:
    """
    Comprehensive threat indicator validator with caching
    """
    
    def __init__(self):
        self._validation_cache = {}
        self._type_cache = {}
    
    def validate(self, indicator: str, expected_type: Optional[str] = None) -> bool:
        """
        Validate indicator with optional expected type
        
        Args:
            indicator: Indicator to validate
            expected_type: Expected indicator type
        
        Returns:
            True if valid
        """
        cache_key = f"{indicator}:{expected_type}"
        if cache_key in self._validation_cache:
            return self._validation_cache[cache_key]
        
        indicator = sanitize_indicator(indicator)
        if not indicator:
            self._validation_cache[cache_key] = False
            return False
        
        detected_type = self.detect_type(indicator)
        
        if expected_type:
            if expected_type != detected_type:
                self._validation_cache[cache_key] = False
                return False
        
        # Perform type-specific validation
        valid = False
        if detected_type == 'ip':
            valid = validate_ip(indicator)
        elif detected_type == 'domain':
            valid = validate_domain(indicator)
        elif detected_type == 'url':
            valid = validate_url(indicator)
        elif detected_type == 'hash':
            valid, _ = validate_hash(indicator)
        elif detected_type == 'cidr':
            valid = validate_cidr(indicator)
        elif detected_type == 'email':
            valid = validate_email(indicator)
        else:
            valid = False
        
        self._validation_cache[cache_key] = valid
        return valid
    
    def detect_type(self, indicator: str) -> str:
        """
        Detect indicator type with caching
        """
        if not indicator:
            return 'unknown'
        
        if indicator in self._type_cache:
            return self._type_cache[indicator]
        
        detected = validate_indicator_type(indicator)
        self._type_cache[indicator] = detected
        return detected
    
    def batch_validate(self, indicators: List[str]) -> List[Tuple[str, bool, str]]:
        """
        Validate multiple indicators at once
        
        Returns:
            List of (indicator, is_valid, detected_type)
        """
        results = []
        for indicator in indicators:
            detected_type = self.detect_type(indicator)
            is_valid = self.validate(indicator)
            results.append((indicator, is_valid, detected_type))
        
        return results
    
    def filter_valid(self, indicators: List[str], 
                    required_type: Optional[str] = None) -> List[str]:
        """
        Filter list to only valid indicators
        """
        valid_indicators = []
        for indicator in indicators:
            if required_type:
                detected = self.detect_type(indicator)
                if detected != required_type:
                    continue
            if self.validate(indicator):
                valid_indicators.append(indicator)
        
        return valid_indicators
    
    def get_validation_stats(self, indicators: List[str]) -> dict:
        """
        Get validation statistics for a list of indicators
        """
        stats = {
            'total': len(indicators),
            'valid': 0,
            'invalid': 0,
            'by_type': {}
        }
        
        for indicator in indicators:
            is_valid = self.validate(indicator)
            detected_type = self.detect_type(indicator)
            
            if is_valid:
                stats['valid'] += 1
            else:
                stats['invalid'] += 1
            
            if detected_type not in stats['by_type']:
                stats['by_type'][detected_type] = {'total': 0, 'valid': 0}
            
            stats['by_type'][detected_type]['total'] += 1
            if is_valid:
                stats['by_type'][detected_type]['valid'] += 1
        
        return stats
    
    def clear_cache(self):
        """Clear validation cache"""
        self._validation_cache.clear()
        self._type_cache.clear()
