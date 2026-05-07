

import math
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from ipaddress import ip_address, IPv4Address

from ..database.mongo_client import MongoDBClient

logger = logging.getLogger(__name__)


class RiskScorer:
    """Advanced risk scoring with multi-factor analysis"""
    
    def __init__(self, db_client: MongoDBClient):
        self.db = db_client
        
        # Factor weights (total = 1.0)
        self.weights = {
            "feed_reputation": 0.20,
            "indicator_age": 0.15,
            "source_diversity": 0.15,
            "indicator_type": 0.15,
            "geographic_risk": 0.10,
            "historical_activity": 0.15,
            "confidence_score": 0.10
        }
        
        # Feed reputation database (0-100)
        self.feed_reputation = {
            "virustotal": 95,
            "alienvault_otx": 85,
            "feodo_tracker": 90,
            "tor_exit_nodes": 60,
            "abuse_ch_ssl": 88,
            "spamhaus_drop": 85,
            "emerging_threats": 80,
            "cisco_talos": 90,
            "manual": 100
        }
        
        # High-risk country codes (based on threat intelligence)
        self.high_risk_countries = ['RU', 'CN', 'IR', 'KP', 'SY', 'VE', 'NG', 'PK']
        self.medium_risk_countries = ['UA', 'BY', 'IN', 'BR', 'MX', 'ZA']
        
        # Indicator type base risk
        self.type_base_risk = {
            "hash": 85,      # Malware hashes are high confidence
            "url": 75,       # Malicious URLs
            "domain": 70,    # Malicious domains
            "ip": 60,        # IP addresses (can change hands)
            "cidr": 65       # CIDR ranges
        }
        
        # Cache for recalculations
        self._score_cache = {}
        self.cache_ttl_seconds = 300  # 5 minutes
    
    def calculate_risk_score(self, indicator: str, threat_data: Dict[str, Any]) -> int:
        """
        Calculate comprehensive risk score (0-100)
        Higher score = more malicious
        """
        # Check cache
        cache_key = f"{indicator}:{hash(str(threat_data))}"
        if cache_key in self._score_cache:
            cached_time, cached_score = self._score_cache[cache_key]
            if (datetime.utcnow() - cached_time).total_seconds() < self.cache_ttl_seconds:
                return cached_score
        
        # Calculate individual factor scores
        scores = {}
        
        # Factor 1: Feed Reputation
        feeds = threat_data.get('source_feeds', [])
        scores['feed_reputation'] = self._calculate_feed_score(feeds)
        
        # Factor 2: Indicator Age (newer = riskier)
        first_seen = threat_data.get('first_seen')
        scores['indicator_age'] = self._calculate_age_score(first_seen)
        
        # Factor 3: Source Diversity
        scores['source_diversity'] = self._calculate_diversity_score(len(feeds))
        
        # Factor 4: Indicator Type
        threat_type = threat_data.get('threat_type', 'ip')
        scores['indicator_type'] = self._calculate_type_score(threat_type)
        
        # Factor 5: Geographic Risk
        geo = threat_data.get('geo_location', {})
        scores['geographic_risk'] = self._calculate_geo_score(geo)
        
        # Factor 6: Historical Activity
        scores['historical_activity'] = self._calculate_historical_score(indicator)
        
        # Factor 7: Confidence Score
        confidence = threat_data.get('confidence', 50)
        scores['confidence_score'] = confidence
        
        # Calculate weighted total
        total_score = 0
        for factor, score in scores.items():
            if score is not None:
                weight = self.weights.get(factor, 0)
                total_score += score * weight
        
        # Normalize to 0-100 integer
        final_score = min(100, max(0, int(round(total_score))))
        
        # Cache the result
        self._score_cache[cache_key] = (datetime.utcnow(), final_score)
        
        # Clean cache if too large
        if len(self._score_cache) > 10000:
            self._clean_cache()
        
        return final_score
    
    def _calculate_feed_score(self, feeds: List[str]) -> float:
        """Calculate score based on feed reputation"""
        if not feeds:
            return 0
        
        total = 0
        for feed in feeds:
            score = self.feed_reputation.get(feed, 50)
            total += score
        
        avg_score = total / len(feeds)
        
        # Bonus for high-quality feeds
        if "virustotal" in feeds or "feodo_tracker" in feeds:
            avg_score = min(100, avg_score + 5)
        
        return avg_score
    
    def _calculate_age_score(self, first_seen: Optional[datetime]) -> float:
        """Calculate score based on indicator age"""
        if not first_seen:
            return 50
        
        age_hours = (datetime.utcnow() - first_seen).total_seconds() / 3600
        
        # Exponential decay: newer = higher score
        # Half-life of 24 hours
        score = 100 * math.exp(-age_hours / 24)
        
        return min(100, max(0, score))
    
    def _calculate_diversity_score(self, num_sources: int) -> float:
        """Calculate score based on number of reporting sources"""
        # 0 sources = 0, 1 source = 40, 3+ sources = 100
        if num_sources == 0:
            return 0
        elif num_sources == 1:
            return 40
        elif num_sources == 2:
            return 70
        else:
            return min(100, 70 + (num_sources - 2) * 10)
    
    def _calculate_type_score(self, threat_type: str) -> float:
        """Calculate base score by indicator type"""
        return self.type_base_risk.get(threat_type, 50)
    
    def _calculate_geo_score(self, geo: Dict[str, Any]) -> float:
        """Calculate score based on geographic location"""
        country_code = geo.get('country_code', '').upper()
        
        if country_code in self.high_risk_countries:
            return 100
        elif country_code in self.medium_risk_countries:
            return 60
        elif country_code:
            return 30
        else:
            return 25  # Unknown location
    
    def _calculate_historical_score(self, indicator: str) -> float:
        """Calculate score based on historical block activity"""
        threat = self.db.db.threat_intel.find_one({"indicator": indicator})
        if not threat:
            return 0
        
        block_count = threat.get('block_count', 0)
        false_positive_count = threat.get('false_positive_count', 0)
        
        # Base score on block count (up to 100)
        block_score = min(100, block_count)
        
        # Reduce score if frequently marked as false positive
        if false_positive_count > 0:
            reduction = min(50, false_positive_count * 10)
            block_score = max(0, block_score - reduction)
        
        return block_score
    
    def _clean_cache(self):
        """Clean expired cache entries"""
        now = datetime.utcnow()
        expired_keys = [
            key for key, (timestamp, _) in self._score_cache.items()
            if (now - timestamp).total_seconds() > self.cache_ttl_seconds
        ]
        for key in expired_keys:
            del self._score_cache[key]
        logger.debug(f"Cleaned {len(expired_keys)} cache entries")
    
    def get_risk_level(self, risk_score: int) -> str:
        """Get risk level description"""
        if risk_score >= 90:
            return "CRITICAL"
        elif risk_score >= 70:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 15:
            return "LOW"
        else:
            return "INFORMATIONAL"
    
    def get_risk_color(self, risk_score: int) -> str:
        """Get color code for UI display"""
        if risk_score >= 90:
            return "#FF0000"  # Red
        elif risk_score >= 70:
            return "#FF6600"  # Orange
        elif risk_score >= 40:
            return "#FFCC00"  # Yellow
        else:
            return "#00CC00"  # Green
    
    def batch_calculate_scores(self, indicators: List[str]) -> Dict[str, int]:
        """Calculate scores for multiple indicators efficiently"""
        results = {}
        
        for indicator in indicators:
            threat = self.db.db.threat_intel.find_one({"indicator": indicator})
            if threat:
                score = self.calculate_risk_score(indicator, threat)
                results[indicator] = score
        
        return results
    
    def update_all_scores(self) -> int:
        """Update risk scores for all active threats"""
        active_threats = self.db.get_active_indicators()
        updated_count = 0
        
        for threat in active_threats:
            threat_data = threat.to_mongo()
            new_score = self.calculate_risk_score(threat.indicator, threat_data)
            
            # Update if score changed significantly
            if abs(new_score - threat.risk_score) >= 5:
                self.db.db.threat_intel.update_one(
                    {"indicator": threat.indicator},
                    {"$set": {"risk_score": new_score}}
                )
                updated_count += 1
        
        logger.info(f"Updated risk scores for {updated_count} threats")
        return updated_count


class ThreatEnricher:
    """Enrich threat indicators with additional context"""
    
    def __init__(self, db_client: MongoDBClient):
        self.db = db_client
        
        # Cache for enrichment data
        self.geo_cache = {}
        self.asn_cache = {}
    
    def enrich_with_geoip(self, ip_address: str) -> Dict[str, Any]:
        """Enrich IP with geolocation data"""
        # Check cache
        if ip_address in self.geo_cache:
            return self.geo_cache[ip_address]
        
        # Mock geo IP data (in production, use MaxMind or similar)
        geo_data = self._mock_geo_lookup(ip_address)
        
        # Cache result
        self.geo_cache[ip_address] = geo_data
        
        return geo_data
    
    def _mock_geo_lookup(self, ip: str) -> Dict[str, Any]:
        """Mock geo lookup - replace with actual GeoIP database"""
        # This is a mock implementation
        # In production, use geoip2 or similar library
        
        # Parse IP octets for deterministic mock data
        parts = ip.split('.')
        if len(parts) == 4:
            first_octet = int(parts[0])
            
            # Mock mappings based on first octet
            if first_octet >= 1 and first_octet <= 50:
                return {
                    "country_code": "US",
                    "country_name": "United States",
                    "city": "New York",
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                    "timezone": "America/New_York"
                }
            elif first_octet >= 80 and first_octet <= 90:
                return {
                    "country_code": "RU",
                    "country_name": "Russia",
                    "city": "Moscow",
                    "latitude": 55.7558,
                    "longitude": 37.6173,
                    "timezone": "Europe/Moscow"
                }
            elif first_octet >= 100 and first_octet <= 110:
                return {
                    "country_code": "CN",
                    "country_name": "China",
                    "city": "Beijing",
                    "latitude": 39.9042,
                    "longitude": 116.4074,
                    "timezone": "Asia/Shanghai"
                }
            else:
                return {
                    "country_code": "Unknown",
                    "country_name": "Unknown",
                    "city": "Unknown",
                    "latitude": 0,
                    "longitude": 0,
                    "timezone": "UTC"
                }
        
        return {
            "country_code": "Unknown",
            "country_name": "Unknown",
            "city": "Unknown",
            "latitude": 0,
            "longitude": 0,
            "timezone": "UTC"
        }
    
    def enrich_with_whois(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with WHOIS data"""
        # Mock WHOIS data
        # In production, use python-whois library
        return {
            "registrar": "Example Registrar",
            "creation_date": "2024-01-01",
            "expiration_date": "2025-01-01",
            "name_servers": ["ns1.example.com", "ns2.example.com"],
            "registrant_country": "Unknown"
        }
    
    def enrich_batch(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple indicators in batch"""
        enriched = []
        
        for indicator in indicators:
            enriched_indicator = indicator.copy()
            
            # Enrich IPs with geo data
            if indicator.get('threat_type') == 'ip':
                geo_data = self.enrich_with_geoip(indicator['indicator'])
                enriched_indicator['geo_location'] = geo_data
            
            # Enrich domains with WHOIS
            if indicator.get('threat_type') == 'domain':
                whois_data = self.enrich_with_whois(indicator['indicator'])
                enriched_indicator['whois'] = whois_data
            
            enriched.append(enriched_indicator)
        
        return enriched