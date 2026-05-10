"""
Integration tests for Threat Intelligence Platform
"""

import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from src.database.mongo_client import MongoDBClient
from src.database.models import ThreatIntel, ThreatType, IntelStatus
from src.aggregators.base_aggregator import BaseAggregator
from src.enforcer.policy_enforcer import FirewallEnforcer
from src.config.settings import config

class TestDatabase(unittest.TestCase):
    """Test database operations"""
    
    @classmethod
    def setUpClass(cls):
        cls.db = MongoDBClient(
            config.database.mongodb_uri,
            "test_threat_intel"
        )
    
    def setUp(self):
        # Clean up before each test
        self.db.db.threat_intel.delete_many({})
        self.db.db.blocking_rules.delete_many({})
    
    def test_insert_threat(self):
        """Test inserting a threat indicator"""
        threat = ThreatIntel(
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            source_feeds=["test_feed"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=85,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=["test"]
        )
        
        result = self.db.upsert_threat_intel(threat)
        self.assertTrue(result)
        
        # Verify insertion
        saved = self.db.db.threat_intel.find_one({"indicator": "192.168.1.100"})
        self.assertIsNotNone(saved)
        self.assertEqual(saved["risk_score"], 85)
    
    def test_get_high_risk_threats(self):
        """Test retrieving high-risk threats"""
        # Insert test data
        threats = [
            ThreatIntel(
                indicator=f"192.168.1.{i}",
                threat_type=ThreatType.IP,
                source_feeds=["test"],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                risk_score=90 + i,
                status=IntelStatus.ACTIVE,
                confidence=90,
                tags=[]
            )
            for i in range(5)
        ]
        
        for threat in threats:
            self.db.upsert_threat_intel(threat)
        
        high_risk = self.db.get_high_risk_threats(min_risk_score=85)
        self.assertGreaterEqual(len(high_risk), 3)
    
    def tearDown(self):
        # Clean up
        self.db.db.threat_intel.delete_many({})
    
    @classmethod
    def tearDownClass(cls):
        cls.db.client.drop_database("test_threat_intel")

class TestThreatValidation(unittest.TestCase):
    """Test threat indicator validation"""
    
    def test_ip_validation(self):
        """Test IP address validation"""
        valid_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8"]
        invalid_ips = ["256.1.1.1", "abc.def.ghi.jkl", "192.168.1"]
        
        for ip in valid_ips:
            self.assertTrue(BaseAggregator._validate_ip(ip))
        
        for ip in invalid_ips:
            self.assertFalse(BaseAggregator._validate_ip(ip))

if __name__ == "__main__":
    unittest.main()
