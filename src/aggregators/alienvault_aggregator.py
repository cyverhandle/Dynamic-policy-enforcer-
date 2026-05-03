from typing import List
import requests
from datetime import datetime, timedelta
import logging

from .base_aggregator import BaseAggregator
from ..config.settings import config

logger = logging.getLogger(__name__)

class AlienVaultAggregator(BaseAggregator):
    """AlienVault OTX aggregator"""
    
    def __init__(self):
        super().__init__(
            name="alienvault_otx",
            risk_score_base=75,
            enabled=bool(config.api.alienvault_api_key)
        )
        self.api_key = config.api.alienvault_api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
    
    def fetch_indicators(self) -> List[str]:
        """Fetch pulses and indicators from AlienVault"""
        if not self.api_key:
            logger.warning("AlienVault API key not configured")
            return []
        
        headers = {"X-OTX-API-KEY": self.api_key}
        indicators = []
        
        # Fetch recent pulses (threat intelligence reports)
        try:
            response = self.session.get(
                f"{self.base_url}/pulses/subscribed",
                headers=headers,
                params={"limit": 20, "modified_since": 
                        (datetime.utcnow() - timedelta(days=1)).isoformat()}
            )
            response.raise_for_status()
            data = response.json()
            
            for pulse in data.get('results', []):
                # Extract indicators from the pulse
                for indicator in pulse.get('indicators', []):
                    indicator_value = indicator.get('indicator')
                    if indicator_value:
                        indicators.append(indicator_value)
                        
        except Exception as e:
            logger.error(f"Error fetching AlienVault pulses: {e}")
        
        # Also fetch from specific threat feeds
        feeds = [
            "pulse_alienvault_default",
            "pulse_alienvault_c2"
        ]
        
        for feed in feeds:
            try:
                response = self.session.get(
                    f"{self.base_url}/pulses/{feed}",
                    headers=headers
                )
                response.raise_for_status()
                data = response.json()
                
                for indicator in data.get('indicators', []):
                    indicator_value = indicator.get('indicator')
                    if indicator_value:
                        indicators.append(indicator_value)
                        
            except Exception as e:
                logger.debug(f"Error fetching feed {feed}: {e}")
        
        return list(set(indicators))  # Remove duplicates
    
    def validate_indicator(self, indicator: str) -> bool:
        """Validate AlienVault indicators"""
        # AlienVault provides various types
        return len(indicator) > 2
    
    def enrich_indicator(self, indicator: str) -> dict:
        """Enrich with AlienVault data"""
        enrichment = {
            'tags': ['alienvault', 'otx'],
            'risk_modifier': 0
        }
        
        if not self.api_key:
            return enrichment
        
        headers = {"X-OTX-API-KEY": self.api_key}
        
        # Try to get indicator details
        try:
            # Determine indicator type
            import re
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', indicator):
                endpoint = f"/indicators/IPv4/{indicator}/general"
            elif indicator.startswith(('http://', 'https://')):
                endpoint = f"/indicators/url/{indicator}/general"
            else:
                endpoint = f"/indicators/domain/{indicator}/general"
            
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Add pulse count as confidence indicator
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                if pulse_count > 5:
                    enrichment['risk_modifier'] += 10
                    enrichment['tags'].append('multiple_pulses')
                elif pulse_count > 0:
                    enrichment['risk_modifier'] += 5
                
                # Add validation
                validation = data.get('validation', [])
                if validation:
                    enrichment['tags'].append('validated')
                    
        except Exception as e:
            logger.debug(f"Could not enrich {indicator}: {e}")
        
        return enrichment
