from typing import List
import requests
import logging
import re

from .base_aggregator import BaseAggregator

logger = logging.getLogger(__name__)

class FeodoAggregator(BaseAggregator):
    """Feodo Tracker aggregator for C2 servers"""
    
    def __init__(self):
        super().__init__(
            name="feodo_tracker",
            risk_score_base=90,
            enabled=True
        )
        self.feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    
    def fetch_indicators(self) -> List[str]:
        """Fetch C2 IP addresses from Feodo Tracker"""
        indicators = []
        
        try:
            response = self.session.get(self.feodo_url)
            response.raise_for_status()
            
            for line in response.text.split('\n'):
                line = line.strip()
                # Skip comments and empty lines
                if line.startswith('#') or not line:
                    continue
                
                # Format: IP,First seen,Last seen,Status,AS,Country
                parts = line.split(',')
                if parts:
                    ip = parts[0].strip()
                    if self.validate_indicator(ip):
                        indicators.append(ip)
                        
        except Exception as e:
            logger.error(f"Error fetching Feodo Tracker data: {e}")
        
        logger.info(f"Fetched {len(indicators)} C2 IPs from Feodo Tracker")
        return indicators
    
    def validate_indicator(self, indicator: str) -> bool:
        """Validate IP address format"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, indicator):
            # Additional validation for octet ranges
            octets = indicator.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return False
    
    def enrich_indicator(self, indicator: str) -> dict:
        """Enrich with Feodo-specific information"""
        return {
            'tags': ['c2_server', 'command_and_control', 'malware'],
            'risk_modifier': 5,  # High confidence for C2
            'related': ['emotet', 'trickbot', 'iceid']  # Known malware families
        }
