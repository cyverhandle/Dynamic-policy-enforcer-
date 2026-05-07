

import unittest
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analytics.risk_scorer import RiskScorer
from src.database.mongo_client import MongoDBClient
from src.database.models import ThreatIntel, ThreatType, IntelStatus
from src.config.settings import config


class TestRiskScorer(unittest.TestCase):
    """Test risk scoring engine"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database and scorer"""
        cls.db = MongoDBClient(
            config.database.mongodb_uri,
            "test_risk_scorer"
        )
        cls.scorer = RiskScorer(cls.db)
    
    def setUp(self):
        """Clean up before each test"""
        self.db.db.threat_intel.delete_many({})
    
    def test_feed_reputation_scoring(self):
        """Test feed reputation scoring"""
        # High reputation feed
        high_score = self.scorer._score_feed_reputation(["virustotal"])
        self.assertGreaterEqual(high_score, 90)
        
        # Medium reputation feed
        medium_score = self.scorer._score_feed_reputation(["tor_exit_nodes"])
        self.assertLess(medium_score, 70)
        
        # Multiple feeds (average)
        multi_score = self.scorer._score_feed_reputation(["virustotal", "feodo_tracker"])
        self.assertAlmostEqual(multi_score, (95 + 90) / 2, delta=1)
    
    def test_age_factor_scoring(self):
        """Test age-based scoring"""
        # New indicator (less than 1 hour)
        new_time = datetime.utcnow()
        new_score = self.scorer._score_age_factor(new_time)
        self.assertGreater(new_score, 90)
        
        # Old indicator (7+ days)
        old_time = datetime.utcnow() - timedelta(days=7)
        old_score = self.scorer._score_age_factor(old_time)
        self.assertLess(old_score, 20)
        
        # Very new (0 hours)
        brand_new = self.scorer._score_age_factor(datetime.utcnow())
        self.assertAlmostEqual(brand_new, 100, delta=5)
    
    def test_source_count_scoring(self):
        """Test source count scoring"""
        # No sources
        self.assertEqual(self.scorer._score_source_count(0), 0)
        
        # One source
        self.assertEqual(self.scorer._score_source_count(1), 33)
        
        # Two sources
        self.assertEqual(self.scorer._score_source_count(2), 66)
        
        # Three or more sources
        self.assertEqual(self.scorer._score_source_count(3), 99)
        self.assertEqual(self.scorer._score_source_count(5), 100)
    
    def test_indicator_type_scoring(self):
        """Test indicator type scoring"""
        # Malware hash (highest risk)
        hash_score = self.scorer._score_indicator_type("hash")
        self.assertEqual(hash_score, 80)
        
        # URL
        url_score = self.scorer._score_indicator_type("url")
        self.assertEqual(url_score, 75)
        
        # Domain
        domain_score = self.scorer._score_indicator_type("domain")
        self.assertEqual(domain_score, 70)
        
        # IP (lowest)
        ip_score = self.scorer._score_indicator_type("ip")
        self.assertEqual(ip_score, 60)
    
    def test_geo_risk_scoring(self):
        """Test geographic risk scoring"""
        # High risk country
        high_geo = self.scorer._score_geo_risk({"country_code": "RU"})
        self.assertEqual(high_geo, 100)
        
        # Medium risk country
        medium_geo = self.scorer._score_geo_risk({"country_code": "UA"})
        self.assertEqual(medium_geo, 60)
        
        # Low risk country
        low_geo = self.scorer._score_geo_risk({"country_code": "US"})
        self.assertEqual(low_geo, 30)
        
        # No geo data
        no_geo = self.scorer._score_geo_risk({})
        self.assertEqual(no_geo, 30)
    
    def test_comprehensive_risk_calculation(self):
        """Test complete risk score calculation"""
        threat_data = {
            "source_feeds": ["virustotal", "feodo_tracker"],
            "first_seen": datetime.utcnow(),
            "threat_type": "hash",
            "geo_location": {"country_code": "RU"},
            "block_count": 50
        }
        
        score = self.scorer.calculate_risk_score("test_indicator", threat_data)
        
        # Should be high (multiple high-quality sources, new, hash type, high-risk geo)
        self.assertGreater(score, 80)
        self.assertLessEqual(score, 100)
    
    def test_low_risk_calculation(self):
        """Test low risk score calculation"""
        threat_data = {
            "source_feeds": ["tor_exit_nodes"],
            "first_seen": datetime.utcnow() - timedelta(days=30),
            "threat_type": "ip",
            "geo_location": {"country_code": "US"},
            "block_count": 0
        }
        
        score = self.scorer.calculate_risk_score("low_risk_indicator", threat_data)
        
        # Should be low (old, single low-rep source, IP type, low-risk geo)
        self.assertLess(score, 50)
    
    def test_historical_activity_scoring(self):
        """Test historical activity scoring"""
        # Insert threat with block history
        threat = ThreatIntel(
            indicator="active_threat.com",
            threat_type=ThreatType.DOMAIN,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=50,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[],
            block_count=75
        )
        self.db.upsert_threat_intel(threat)
        
        # Score should be high due to block count
        score = self.scorer._score_historical_activity("active_threat.com")
        self.assertEqual(score, 75)
        
        # New threat with no history
        score_zero = self.scorer._score_historical_activity("new_threat.com")
        self.assertEqual(score_zero, 0)
    
    def test_recalculate_all_scores(self):
        """Test bulk score recalculation"""
        # Insert threats with placeholder scores
        threats = [
            ThreatIntel(
                indicator=f"test_{i}.com",
                threat_type=ThreatType.DOMAIN,
                source_feeds=["virustotal"],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                risk_score=0,  # Will be recalculated
                status=IntelStatus.ACTIVE,
                confidence=90,
                tags=[]
            )
            for i in range(5)
        ]
        
        for threat in threats:
            self.db.upsert_threat_intel(threat)
        
        # Recalculate all scores
        updated = self.scorer.recalculate_all_scores()
        
        self.assertEqual(updated, 5)
        
        # Verify new scores are reasonable
        for i in range(5):
            threat = self.db.db.threat_intel.find_one({"indicator": f"test_{i}.com"})
            self.assertGreater(threat['risk_score'], 0)
            self.assertLessEqual(threat['risk_score'], 100)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up"""
        cls.db.client.drop_database("test_risk_scorer")


if __name__ == "__main__":
    unittest.main()