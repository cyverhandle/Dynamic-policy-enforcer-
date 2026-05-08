from typing import List
import requests
import logging
import re

from .base_aggregator import BaseAggregator

logger = logging.getLogger(__name__)

class TorExitNodeAggregator(BaseAggregator):
    """Tor exit node aggregator"""
    
    def __init__(self):
        super().__init__(
            name="tor_exit_nodes",
            risk_score_base=60,
            enabled=True
        )
        self.tor_url = "https://check.torproject.org/torbulkexitlist"
    
    def fetch_indicators(self) -> List[str]:
        """Fetch Tor exit node IPs"""
        indicators = []
        
        try:
            response = self.session.get(self.tor_url)
            response.raise_for_status()
            
            for line in response.text.split('\n'):
                line = line.strip()
                if line and self.validate_indicator(line):
                    indicators.append(line)
                    
        except Exception as e:
            logger.error(f"Error fetching Tor exit nodes: {e}")
        
        logger.info(f"Fetched {len(indicators)} Tor exit nodes")
        return indicators
    
    def validate_indicator(self, indicator: str) -> bool:
        """Validate IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, indicator):
            octets = indicator.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return False
    
    def enrich_indicator(self, indicator: str) -> dict:
        """Enrich Tor-specific info"""
        return {
            'tags': ['tor', 'exit_node', 'anonymizer'],
            'risk_modifier': 0,  # Tor itself isn't malicious, but often used for abuse
            'related': []
        }
