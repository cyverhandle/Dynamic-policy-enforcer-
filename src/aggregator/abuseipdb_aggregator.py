"""
AbuseIPDB Aggregator - Fetches malicious IP reports from AbuseIPDB
"""

from typing import List, Dict, Any
import requests
from datetime import datetime, timedelta
import logging

from .base_aggregator import BaseAggregator
from ..config.settings import config
from ..database.models import ThreatIntel, ThreatType, IntelStatus

logger = logging.getLogger(__name__)

class AbuseIPDBAggregator(BaseAggregator):
    """AbuseIPDB aggregator for malicious IP intelligence"""
    
    def __init__(self):
        super().__init__(
            name="abuseipdb",
            risk_score_base=80,
            enabled=bool(config.api.abuseipdb_api_key)
        )
        self.api_key = config.api.abuseipdb_api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        
        # Categories mapping
        self.category_map = {
            1: "DNS_Compromise",
            2: "DNS_Poisoning",
            3: "Fraud_Orders",
            4: "DDoS_Attack",
            5: "FTP_Brute_Force",
            6: "Ping_of_Death",
            7: "Phishing",
            8: "Fraud_Voice",
            9: "Fraud_Identity_Theft",
            10: "Email_Spam",
            11: "Brute_Force",
            12: "Bad_Web_Bot",
            13: "Exploited_Server",
            14: "Web_App_Attack",
            15: "SSH_Attack",
            16: "IoT_Targeted"
        }
    
    def fetch_indicators(self) -> List[str]:
        """Fetch recent malicious IPs from AbuseIPDB"""
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return []
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        indicators = []
        
        # Fetch recent blacklisted IPs (last 7 days)
        try:
            # Get most recent reports
            params = {
                "confidenceMinimum": 50,  # Only moderate to high confidence
                "maxAgeInDays": 7,        # Last 7 days
                "limit": 100,             # Max 100 IPs per request
                "onlyCountries": [],      # Optional: filter by country
                "ipVersion": 4            # IPv4 only
            }
            
            response = self.session.get(
                f"{self.base_url}/blacklist",
                headers=headers,
                params=params
            )
            response.raise_for_status()
            data = response.json()
            
            # Extract IPs from blacklist
            for item in data.get('data', []):
                ip = item.get('ipAddress')
                if ip and self.validate_indicator(ip):
                    indicators.append(ip)
                    
            logger.info(f"Fetched {len(indicators)} malicious IPs from AbuseIPDB blacklist")
            
        except Exception as e:
            logger.error(f"Error fetching AbuseIPDB blacklist: {e}")
        
        # Also fetch from recent reports endpoint
        try:
            params = {
                "limit": 50,
                "days": 7
            }
            
            response = self.session.get(
                f"{self.base_url}/recent",
                headers=headers,
                params=params
            )
            response.raise_for_status()
            data = response.json()
            
            for report in data.get('data', []):
                ip = report.get('ipAddress')
                if ip and self.validate_indicator(ip) and ip not in indicators:
                    indicators.append(ip)
                    
        except Exception as e:
            logger.error(f"Error fetching AbuseIPDB recent reports: {e}")
        
        return list(set(indicators))  # Remove duplicates
    
    def check_single_ip(self, ip_address: str) -> Dict[str, Any]:
        """Check a specific IP address for detailed information"""
        if not self.api_key:
            return {}
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        try:
            response = self.session.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Error checking IP {ip_address}: {e}")
            return {}
    
    def validate_indicator(self, indicator: str) -> bool:
        """Validate IP address format"""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, indicator):
            octets = indicator.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return False
    
    def enrich_indicator(self, indicator: str) -> dict:
        """Enrich indicator with AbuseIPDB detailed data"""
        enrichment = {
            'tags': ['abuseipdb', 'malicious'],
            'risk_modifier': 0,
            'geo_location': None,
            'related': [],
            'category_names': []
        }
        
        if not self.api_key:
            return enrichment
        
        # Get detailed IP information
        ip_data = self.check_single_ip(indicator)
        
        if ip_data and 'data' in ip_data:
            data = ip_data['data']
            
            # Add confidence score
            confidence = data.get('abuseConfidenceScore', 0)
            if confidence >= 90:
                enrichment['risk_modifier'] += 20
                enrichment['tags'].append('high_confidence')
            elif confidence >= 70:
                enrichment['risk_modifier'] += 10
                enrichment['tags'].append('medium_confidence')
            elif confidence >= 50:
                enrichment['risk_modifier'] += 5
            
            # Add categories
            categories = data.get('categories', [])
            category_names = []
            for cat_id in categories:
                if cat_id in self.category_map:
                    category_names.append(self.category_map[cat_id])
            
            enrichment['category_names'] = category_names
            enrichment['tags'].extend(category_names[:3])  # Add top 3 categories as tags
            
            # Add country information
            country_code = data.get('countryCode')
            country_name = data.get('countryName')
            if country_code:
                enrichment['geo_location'] = {
                    'country_code': country_code,
                    'country_name': country_name
                }
                enrichment['tags'].append(f'country_{country_code.lower()}')
            
            # Add total reports
            total_reports = data.get('totalReports', 0)
            if total_reports > 10:
                enrichment['risk_modifier'] += 5
                enrichment['tags'].append('multiple_reports')
            
            # Add last reported timestamp
            last_reported = data.get('lastReportedAt')
            if last_reported:
                enrichment['last_reported'] = last_reported
            
            # Calculate risk multiplier based on categories
            high_risk_categories = ['Phishing', 'Malware', 'C2', 'Exploited_Server']
            for cat in category_names:
                if cat in high_risk_categories:
                    enrichment['risk_modifier'] += 5
        
        return enrichment
    
    def create_threat_intel(self, indicator: str) -> ThreatIntel:
        """Override to add AbuseIPDB-specific enrichment"""
        if not self.validate_indicator(indicator):
            return None
        
        enrichment = self.enrich_indicator(indicator)
        
        # Calculate final risk score
        risk_score = self.risk_score_base + enrichment.get('risk_modifier', 0)
        risk_score = min(100, risk_score)  # Cap at 100
        
        # Determine severity based on confidence
        confidence = 70
        if 'high_confidence' in enrichment.get('tags', []):
            confidence = 95
        elif 'medium_confidence' in enrichment.get('tags', []):
            confidence = 80
        
        return ThreatIntel(
            indicator=indicator,
            threat_type=ThreatType.IP,
            source_feeds=[self.name],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=risk_score,
            severity=None,  # Will be auto-calculated
            status=IntelStatus.ACTIVE,
            confidence=confidence,
            tags=enrichment.get('tags', ['abuseipdb']),
            geo_location=enrichment.get('geo_location'),
            related_indicators=enrichment.get('related', [])
        )
