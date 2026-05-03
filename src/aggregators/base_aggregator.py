from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..database.models import ThreatIntel, ThreatType, IntelStatus
from ..utils.logger import get_logger

logger = get_logger(__name__)

class BaseAggregator(ABC):
    """Base class for all threat feed aggregators"""
    
    def __init__(self, name: str, risk_score_base: int, enabled: bool = True):
        self.name = name
        self.risk_score_base = risk_score_base
        self.enabled = enabled
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.timeout = 30
        return session
    
    @abstractmethod
    def fetch_indicators(self) -> List[str]:
        """Fetch raw indicators from the feed"""
        pass
    
    @abstractmethod
    def validate_indicator(self, indicator: str) -> bool:
        """Validate indicator format"""
        pass
    
    def enrich_indicator(self, indicator: str) -> dict:
        """Enrich indicator with additional data (override for custom enrichment)"""
        return {}
    
    def create_threat_intel(self, indicator: str) -> Optional[ThreatIntel]:
        """Convert raw indicator to ThreatIntel object"""
        if not self.validate_indicator(indicator):
            logger.warning(f"Invalid indicator format: {indicator} from {self.name}")
            return None
        
        enrichment = self.enrich_indicator(indicator)
        
        # Determine threat type
        threat_type = self._determine_threat_type(indicator)
        
        return ThreatIntel(
            indicator=indicator,
            threat_type=threat_type,
            source_feeds=[self.name],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=self.risk_score_base + enrichment.get('risk_modifier', 0),
            severity=None,  # Will be auto-calculated
            status=IntelStatus.ACTIVE,
            confidence=80,
            tags=enrichment.get('tags', []),
            geo_location=enrichment.get('geo_location'),
            related_indicators=enrichment.get('related', [])
        )
    
    def _determine_threat_type(self, indicator: str) -> ThreatType:
        """Determine threat type from indicator format"""
        import re
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, indicator):
            return ThreatType.IP
        
        # CIDR pattern
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        if re.match(cidr_pattern, indicator):
            return ThreatType.CIDR
        
        # Domain pattern (simple)
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}$'
        if re.match(domain_pattern, indicator):
            return ThreatType.DOMAIN
        
        # URL pattern
        if indicator.startswith(('http://', 'https://')):
            return ThreatType.URL
        
        # Hash pattern (MD5, SHA1, SHA256)
        hash_patterns = [
            r'^[a-fA-F0-9]{32}$',   # MD5
            r'^[a-fA-F0-9]{40}$',   # SHA1
            r'^[a-fA-F0-9]{64}$'    # SHA256
        ]
        for pattern in hash_patterns:
            if re.match(pattern, indicator):
                return ThreatType.HASH
        
        return ThreatType.URL  # Default
    
    def collect(self) -> List[ThreatIntel]:
        """Main collection method"""
        if not self.enabled:
            logger.info(f"Aggregator {self.name} is disabled")
            return []
        
        try:
            logger.info(f"Fetching indicators from {self.name}")
            indicators = self.fetch_indicators()
            logger.info(f"Retrieved {len(indicators)} raw indicators from {self.name}")
            
            threat_intels = []
            for indicator in indicators:
                threat_intel = self.create_threat_intel(indicator)
                if threat_intel:
                    threat_intels.append(threat_intel)
            
            logger.info(f"Created {len(threat_intels)} ThreatIntel objects from {self.name}")
            return threat_intels
            
        except Exception as e:
            logger.error(f"Error collecting from {self.name}: {e}")
            return []
