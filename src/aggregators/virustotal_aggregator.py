from typing import List
import requests
from datetime import datetime, timedelta
import logging

from .base_aggregator import BaseAggregator
from ..config.settings import config

logger = logging.getLogger(__name__)

class VirusTotalAggregator(BaseAggregator):
    """VirusTotal API aggregator for threat intelligence"""
    
    def __init__(self):
        super().__init__(
            name="virustotal",
            risk_score_base=85,
            enabled=bool(config.api.virustotal_api_key)
        )
        self.api_key = config.api.virustotal_api_key
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def fetch_indicators(self) -> List[str]:
        """Fetch recent malicious indicators from VirusTotal"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return []
        
        headers = {"x-apikey": self.api_key}
        
        # Fetch recently submitted URLs that are malicious
        indicators = []
        
        # Get recent malicious URLs
        try:
            response = self.session.get(
                f"{self.base_url}/urls",
                headers=headers,
                params={"limit": 40}
            )
            response.raise_for_status()
            data = response.json()
            
            for item in data.get('data', []):
                url = item.get('attributes', {}).get('url')
                if url:
                    # Check if URL is malicious
                    last_analysis_stats = item.get('attributes', {}).get('last_analysis_stats', {})
                    malicious_count = last_analysis_stats.get('malicious', 0)
                    if malicious_count > 0:
                        indicators.append(url)
                        
        except Exception as e:
            logger.error(f"Error fetching VirusTotal URLs: {e}")
        
        # Get recent malicious IP addresses
        try:
            # VirusTotal requires IP as a separate endpoint
            # For demo, we'll use a set of known malicious IPs from reputation
            response = self.session.get(
                f"{self.base_url}/ip_addresses",
                headers=headers,
                params={"limit": 40}
            )
            response.raise_for_status()
            data = response.json()
            
            for item in data.get('data', []):
                ip = item.get('id')
                if ip:
                    stats = item.get('attributes', {}).get('last_analysis_stats', {})
                    malicious_count = stats.get('malicious', 0)
                    if malicious_count > 0:
                        indicators.append(ip)
                        
        except Exception as e:
            logger.error(f"Error fetching VirusTotal IPs: {e}")
        
        return list(set(indicators))  # Remove duplicates
    
    def validate_indicator(self, indicator: str) -> bool:
        """Validate indicator format for VirusTotal"""
        # URLs and IPs are valid
        return len(indicator) > 3
    
    def enrich_indicator(self, indicator: str) -> dict:
        """Enrich with VirusTotal-specific data"""
        enrichment = {
            'tags': ['virustotal', 'malicious'],
            'risk_modifier': 0
        }
        
        if not self.api_key:
            return enrichment
        
        headers = {"x-apikey": self.api_key}
        
        # Try to get detailed info for the indicator
        try:
            # Determine appropriate endpoint
            if indicator.startswith(('http://', 'https://')):
                # Need to encode URL
                import base64
                url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip('=')
                response = self.session.get(
                    f"{self.base_url}/urls/{url_id}",
                    headers=headers
                )
            else:
                response = self.session.get(
                    f"{self.base_url}/ip_addresses/{indicator}",
                    headers=headers
                )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # Add additional tags based on analysis
                stats = attributes.get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                total_engines = sum(stats.values())
                
                if total_engines > 0:
                    detection_rate = malicious_count / total_engines
                    if detection_rate > 0.5:
                        enrichment['risk_modifier'] = 15
                        enrichment['tags'].append('highly_malicious')
                    elif detection_rate > 0.2:
                        enrichment['risk_modifier'] = 5
                
                # Add reputation if available
                reputation = attributes.get('reputation')
                if reputation and reputation < 0:
                    enrichment['tags'].append('bad_reputation')
                    enrichment['risk_modifier'] += 10
                    
        except Exception as e:
            logger.debug(f"Could not enrich {indicator}: {e}")
        
        return enrichment
