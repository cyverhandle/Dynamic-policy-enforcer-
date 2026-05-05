

import hashlib
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
from difflib import SequenceMatcher

from src.database.models import ThreatIntel, ThreatType
from src.config.settings import config

logger = logging.getLogger(__name__)

class ThreatDeduplicator:
    """
    Advanced deduplication engine for threat intelligence
    Handles exact duplicates, near-duplicates, and related indicators
    """
    
    def __init__(self, db_client=None):
        self.db_client = db_client
        self.similarity_threshold = 0.85  # 85% similarity for fuzzy matching
        self.normalization_cache = {}
        
        # Domain variations to normalize
        self.domain_normalizations = {
            'www.': '',
            'http://': '',
            'https://': '',
            'ftp://': '',
        }
    
    def normalize_indicator(self, indicator: str, threat_type: ThreatType = None) -> str:
        """
        Normalize indicator to canonical form for comparison
        """
        # Check cache
        cache_key = f"{indicator}_{threat_type}"
        if cache_key in self.normalization_cache:
            return self.normalization_cache[cache_key]
        
        normalized = indicator.lower().strip()
        
        # Remove protocol prefixes
        for prefix, replacement in self.domain_normalizations.items():
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        
        # Remove trailing slashes for URLs
        if normalized.endswith('/'):
            normalized = normalized.rstrip('/')
        
        # Remove port numbers from IPs (optional)
        if threat_type == ThreatType.IP and ':' in normalized:
            normalized = normalized.split(':')[0]
        
        # Normalize CIDR notation
        if threat_type == ThreatType.CIDR:
            # Ensure consistent format
            if '/' in normalized:
                parts = normalized.split('/')
                if len(parts) == 2:
                    # Validate CIDR is in standard form
                    network, mask = parts
                    if '.' in network:
                        normalized = f"{network}/{mask}"
        
        # Cache result
        self.normalization_cache[cache_key] = normalized
        return normalized
    
    def create_indicator_hash(self, indicator: str, threat_type: ThreatType = None) -> str:
        """
        Create a hash fingerprint for an indicator
        """
        normalized = self.normalize_indicator(indicator, threat_type)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def find_exact_duplicates(self, threats: List[ThreatIntel]) -> Dict[str, List[ThreatIntel]]:
        """
        Find exact duplicate indicators
        Returns dict mapping hash to list of duplicate threats
        """
        hash_map = defaultdict(list)
        
        for threat in threats:
            threat_hash = self.create_indicator_hash(threat.indicator, threat.threat_type)
            hash_map[threat_hash].append(threat)
        
        # Return only duplicates (lists with more than 1)
        return {h: threats for h, threats in hash_map.items() if len(threats) > 1}
    
    def find_fuzzy_duplicates(self, threats: List[ThreatIntel]) -> List[Tuple[ThreatIntel, ThreatIntel, float]]:
        """
        Find similar/near-duplicate indicators using fuzzy matching
        """
        similar_pairs = []
        threats_list = list(threats)
        
        for i in range(len(threats_list)):
            for j in range(i + 1, len(threats_list)):
                threat1 = threats_list[i]
                threat2 = threats_list[j]
                
                # Only compare same types
                if threat1.threat_type != threat2.threat_type:
                    continue
                
                # Calculate similarity
                similarity = self._calculate_similarity(
                    threat1.indicator,
                    threat2.indicator,
                    threat1.threat_type
                )
                
                if similarity >= self.similarity_threshold:
                    similar_pairs.append((threat1, threat2, similarity))
        
        return similar_pairs
    
    def _calculate_similarity(self, indicator1: str, indicator2: str, threat_type: ThreatType) -> float:
        """
        Calculate similarity between two indicators based on type
        """
        norm1 = self.normalize_indicator(indicator1, threat_type)
        norm2 = self.normalize_indicator(indicator2, threat_type)
        
        if threat_type == ThreatType.IP:
            # For IPs, exact match or CIDR containment
            if norm1 == norm2:
                return 1.0
            # Check if one IP is in the other's CIDR range
            if self._ip_in_network(norm1, norm2) or self._ip_in_network(norm2, norm1):
                return 0.95
            return 0.0
        
        elif threat_type == ThreatType.DOMAIN:
            # For domains, check if one is subdomain of another
            if norm1.endswith(norm2) or norm2.endswith(norm1):
                return 0.9
            # Use sequence matching for domain similarity
            return SequenceMatcher(None, norm1, norm2).ratio()
        
        elif threat_type == ThreatType.URL:
            # For URLs, compare paths after domain
            return self._compare_urls(norm1, norm2)
        
        elif threat_type == ThreatType.HASH:
            # For hashes, exact match only
            return 1.0 if norm1 == norm2 else 0.0
        
        else:
            return SequenceMatcher(None, norm1, norm2).ratio()
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """
        Check if an IP address belongs to a CIDR network
        """
        try:
            from ipaddress import ip_address, ip_network
            if '/' in network:
                return ip_address(ip) in ip_network(network, strict=False)
            return ip == network
        except Exception:
            return False
    
    def _compare_urls(self, url1: str, url2: str) -> float:
        """
        Compare URLs with special handling for paths and parameters
        """
        from urllib.parse import urlparse
        
        try:
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            
            # Same domain and path
            if parsed1.netloc == parsed2.netloc and parsed1.path == parsed2.path:
                return 0.95
            
            # Same domain only
            if parsed1.netloc == parsed2.netloc:
                return 0.7
            
            # Check if paths are similar
            return SequenceMatcher(None, url1, url2).ratio()
        except Exception:
            return SequenceMatcher(None, url1, url2).ratio()
    
    def merge_duplicate_threats(self, duplicates: List[ThreatIntel]) -> ThreatIntel:
        """
        Merge multiple duplicate threat records into a single consolidated record
        """
        if not duplicates:
            return None
        
        # Use the first threat as base
        primary = duplicates[0]
        
        # Merge source feeds
        all_feeds = set()
        all_tags = set()
        all_related = set()
        max_risk = primary.risk_score
        
        for threat in duplicates:
            all_feeds.update(threat.source_feeds)
            all_tags.update(threat.tags)
            all_related.update(threat.related_indicators)
            max_risk = max(max_risk, threat.risk_score)
        
        # Calculate confidence based on number of sources
        confidence = min(100, 50 + len(all_feeds) * 10)
        
        # Update primary with merged data
        primary.source_feeds = list(all_feeds)
        primary.tags = list(all_tags)
        primary.related_indicators = list(all_related)
        primary.risk_score = max_risk
        primary.confidence = confidence
        primary.last_seen = max(threat.last_seen for threat in duplicates)
        
        return primary
    
    def deduplicate_threats(self, threats: List[ThreatIntel], 
                           in_place: bool = True) -> List[ThreatIntel]:
        """
        Main deduplication pipeline
        Returns deduplicated list of threats
        """
        if not threats:
            return []
        
        logger.info(f"Starting deduplication for {len(threats)} threats")
        
        # Step 1: Find exact duplicates
        exact_duplicates = self.find_exact_duplicates(threats)
        
        # Step 2: Merge exact duplicates
        merged_threats = []
        processed_hashes = set()
        
        for threat_hash, duplicate_group in exact_duplicates.items():
            if threat_hash not in processed_hashes:
                merged = self.merge_duplicate_threats(duplicate_group)
                merged_threats.append(merged)
                processed_hashes.add(threat_hash)
        
        # Add non-duplicate threats
        for threat in threats:
            threat_hash = self.create_indicator_hash(threat.indicator, threat.threat_type)
            if threat_hash not in processed_hashes:
                merged_threats.append(threat)
                processed_hashes.add(threat_hash)
        
        # Step 3: Find fuzzy duplicates
        fuzzy_duplicates = self.find_fuzzy_duplicates(merged_threats)
        
        # Step 4: Merge fuzzy duplicates
        fuzzy_processed = set()
        final_threats = []
        
        for threat1, threat2, similarity in fuzzy_duplicates:
            if threat1.indicator in fuzzy_processed or threat2.indicator in fuzzy_processed:
                continue
            
            # Merge fuzzy duplicates
            merged = self.merge_duplicate_threats([threat1, threat2])
            final_threats.append(merged)
            fuzzy_processed.add(threat1.indicator)
            fuzzy_processed.add(threat2.indicator)
            
            logger.info(f"Merged fuzzy duplicates: {threat1.indicator} <-> {threat2.indicator} "
                       f"(similarity: {similarity:.2f})")
        
        # Add remaining threats
        for threat in merged_threats:
            if threat.indicator not in fuzzy_processed:
                final_threats.append(threat)
        
        logger.info(f"Deduplication complete: {len(threats)} -> {len(final_threats)} threats")
        
        # Update database if client provided
        if self.db_client and in_place:
            self._update_database(threats, final_threats)
        
        return final_threats
    
    def _update_database(self, original_threats: List[ThreatIntel], 
                        deduplicated_threats: List[ThreatIntel]):
        """
        Update database with deduplicated threats
        """
        try:
            # Clear original threats from temporary collection
            temp_collection = self.db_client.db.deduplication_temp
            temp_collection.delete_many({})
            
            # Insert deduplicated threats
            for threat in deduplicated_threats:
                temp_collection.update_one(
                    {"indicator": threat.indicator},
                    {"$set": threat.to_mongo()},
                    upsert=True
                )
            
            logger.info(f"Database updated with deduplicated threats")
            
        except Exception as e:
            logger.error(f"Failed to update database with deduplicated threats: {e}")
    
    def is_duplicate(self, threat: ThreatIntel, existing_threats: List[ThreatIntel]) -> bool:
        """
        Check if a threat is a duplicate of any existing threats
        """
        threat_hash = self.create_indicator_hash(threat.indicator, threat.threat_type)
        
        for existing in existing_threats:
            existing_hash = self.create_indicator_hash(existing.indicator, existing.threat_type)
            
            if threat_hash == existing_hash:
                return True
            
            # Check for fuzzy match
            similarity = self._calculate_similarity(
                threat.indicator, 
                existing.indicator, 
                threat.threat_type
            )
            if similarity >= self.similarity_threshold:
                return True
        
        return False
    
    def find_related_indicators(self, indicator: str, threats: List[ThreatIntel], 
                                max_results: int = 10) -> List[ThreatIntel]:
        """
        Find indicators related to the given indicator
        """
        related = []
        
        for threat in threats:
            # Same threat type and similar
            if self._calculate_similarity(indicator, threat.indicator, threat.threat_type) > 0.6:
                related.append(threat)
            
            # Check tags
            if hasattr(threat, 'tags') and threat.tags:
                if any(tag in indicator.lower() for tag in threat.tags):
                    related.append(threat)
            
            # Check related indicators
            if hasattr(threat, 'related_indicators') and threat.related_indicators:
                if indicator in threat.related_indicators:
                    related.append(threat)
        
        # Remove duplicates and limit
        seen = set()
        unique_related = []
        for threat in related:
            if threat.indicator not in seen:
                seen.add(threat.indicator)
                unique_related.append(threat)
                if len(unique_related) >= max_results:
                    break
        
        return unique_related
    
    def get_statistics(self, threats: List[ThreatIntel]) -> Dict[str, Any]:
        """
        Get deduplication statistics
        """
        exact_duplicates = self.find_exact_duplicates(threats)
        fuzzy_duplicates = self.find_fuzzy_duplicates(threats)
        
        # Count by threat type
        type_counts = defaultdict(int)
        for threat in threats:
            type_counts[threat.threat_type.value] += 1
        
        return {
            "total_threats": len(threats),
            "exact_duplicate_groups": len(exact_duplicates),
            "fuzzy_duplicate_pairs": len(fuzzy_duplicates),
            "duplicate_percentage": (len(exact_duplicates) * 100 / len(threats)) if threats else 0,
            "threats_by_type": dict(type_counts),
            "normalization_cache_size": len(self.normalization_cache)
        }


class IndicatorWhitelist:
    """
    Whitelist management for false positives and trusted indicators
    """
    
    def __init__(self, db_client=None):
        self.db_client = db_client
        self.whitelist_cache = set()
        self._load_whitelist()
    
    def _load_whitelist(self):
        """Load whitelist from database"""
        if self.db_client:
            try:
                whitelist = self.db_client.db.whitelist.find({})
                for item in whitelist:
                    self.whitelist_cache.add(item['indicator'])
                logger.info(f"Loaded {len(self.whitelist_cache)} whitelisted indicators")
            except Exception as e:
                logger.error(f"Failed to load whitelist: {e}")
    
    def add_to_whitelist(self, indicator: str, reason: str, added_by: str = "system") -> bool:
        """Add indicator to whitelist"""
        try:
            self.whitelist_cache.add(indicator)
            
            if self.db_client:
                self.db_client.db.whitelist.update_one(
                    {"indicator": indicator},
                    {
                        "$set": {
                            "indicator": indicator,
                            "reason": reason,
                            "added_by": added_by,
                            "added_at": datetime.utcnow()
                        }
                    },
                    upsert=True
                )
            
            logger.info(f"Added {indicator} to whitelist: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add to whitelist: {e}")
            return False
    
    def remove_from_whitelist(self, indicator: str) -> bool:
        """Remove indicator from whitelist"""
        try:
            self.whitelist_cache.discard(indicator)
            
            if self.db_client:
                result = self.db_client.db.whitelist.delete_one({"indicator": indicator})
                return result.deleted_count > 0
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove from whitelist: {e}")
            return False
    
    def is_whitelisted(self, indicator: str) -> bool:
        """Check if indicator is whitelisted"""
        return indicator in self.whitelist_cache
    
    def get_whitelist(self) -> List[Dict[str, Any]]:
        """Get full whitelist"""
        if self.db_client:
            return list(self.db_client.db.whitelist.find({}, {"_id": 0}))
        return [{"indicator": i} for i in self.whitelist_cache]
