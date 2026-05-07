
import unittest
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database.mongo_client import MongoDBClient
from src.database.models import (
    ThreatIntel, ThreatType, IntelStatus, 
    ThreatSeverity, BlockingRule, AuditLog
)
from src.config.settings import config


class TestDatabaseModels(unittest.TestCase):
    """Test database model classes"""
    
    def test_threat_intel_creation(self):
        """Test ThreatIntel model creation"""
        threat = ThreatIntel(
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            source_feeds=["test_feed"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=85,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=["malware", "c2"]
        )
        
        self.assertEqual(threat.indicator, "192.168.1.100")
        self.assertEqual(threat.threat_type, ThreatType.IP)
        self.assertEqual(threat.risk_score, 85)
        self.assertEqual(threat.severity, ThreatSeverity.HIGH)  # 85 >= 70
    
    def test_severity_calculation(self):
        """Test automatic severity calculation"""
        # Critical (90+)
        threat_critical = ThreatIntel(
            indicator="test1",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=95,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        self.assertEqual(threat_critical.severity, ThreatSeverity.CRITICAL)
        
        # High (70-89)
        threat_high = ThreatIntel(
            indicator="test2",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=75,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        self.assertEqual(threat_high.severity, ThreatSeverity.HIGH)
        
        # Medium (40-69)
        threat_medium = ThreatIntel(
            indicator="test3",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=50,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        self.assertEqual(threat_medium.severity, ThreatSeverity.MEDIUM)
        
        # Low (0-39)
        threat_low = ThreatIntel(
            indicator="test4",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=20,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        self.assertEqual(threat_low.severity, ThreatSeverity.LOW)
    
    def test_threat_intel_to_mongo(self):
        """Test conversion to MongoDB document"""
        threat = ThreatIntel(
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            source_feeds=["test_feed"],
            first_seen=datetime(2024, 1, 1, 12, 0, 0),
            last_seen=datetime(2024, 1, 1, 12, 0, 0),
            risk_score=85,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=["test"]
        )
        
        doc = threat.to_mongo()
        
        self.assertEqual(doc['indicator'], "192.168.1.100")
        self.assertEqual(doc['threat_type'], "ip")
        self.assertEqual(doc['severity'], "high")
        self.assertEqual(doc['status'], "active")
    
    def test_blocking_rule_expiration(self):
        """Test blocking rule expiration logic"""
        # Non-expired rule
        rule_active = BlockingRule(
            rule_id="rule_001",
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            created_by="auto",
            reason="high_risk",
            risk_score=85
        )
        self.assertFalse(rule_active.is_expired())
        
        # Expired rule
        rule_expired = BlockingRule(
            rule_id="rule_002",
            indicator="192.168.1.101",
            threat_type=ThreatType.IP,
            created_at=datetime.utcnow() - timedelta(days=2),
            expires_at=datetime.utcnow() - timedelta(hours=1),
            created_by="auto",
            reason="high_risk",
            risk_score=85
        )
        self.assertTrue(rule_expired.is_expired())
    
    def test_audit_log_creation(self):
        """Test audit log creation"""
        audit = AuditLog(
            timestamp=datetime.utcnow(),
            action="block_added",
            indicator="192.168.1.100",
            user_or_system="auto",
            details={"risk_score": 85, "reason": "high_risk"}
        )
        
        self.assertEqual(audit.action, "block_added")
        self.assertEqual(audit.indicator, "192.168.1.100")
        self.assertEqual(audit.user_or_system, "auto")


class TestMongoDBClient(unittest.TestCase):
    """Test MongoDB client operations (requires running MongoDB)"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database"""
        cls.db = MongoDBClient(
            config.database.mongodb_uri,
            "test_threat_intel"
        )
    
    def setUp(self):
        """Clean up before each test"""
        self.db.db.threat_intel.delete_many({})
        self.db.db.blocking_rules.delete_many({})
        self.db.db.audit_logs.delete_many({})
    
    def test_upsert_threat_intel_insert(self):
        """Test inserting new threat intelligence"""
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
        self.assertEqual(saved['risk_score'], 85)
    
    def test_upsert_threat_intel_update(self):
        """Test updating existing threat intelligence"""
        # Insert first
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
        self.db.upsert_threat_intel(threat)
        
        # Update with new risk score
        threat.risk_score = 95
        threat.source_feeds.append("second_feed")
        
        result = self.db.upsert_threat_intel(threat)
        self.assertTrue(result)
        
        # Verify update
        saved = self.db.db.threat_intel.find_one({"indicator": "192.168.1.100"})
        self.assertEqual(saved['risk_score'], 95)
        self.assertIn("second_feed", saved['source_feeds'])
    
    def test_bulk_upsert_threat_intel(self):
        """Test bulk insert/update"""
        threats = []
        for i in range(10):
            threat = ThreatIntel(
                indicator=f"192.168.1.{i}",
                threat_type=ThreatType.IP,
                source_feeds=["test_feed"],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                risk_score=50 + i,
                status=IntelStatus.ACTIVE,
                confidence=90,
                tags=[]
            )
            threats.append(threat)
        
        result = self.db.bulk_upsert_threat_intel(threats)
        self.assertEqual(result['inserted'], 10)
        
        # Verify count
        count = self.db.db.threat_intel.count_documents({})
        self.assertEqual(count, 10)
    
    def test_get_high_risk_threats(self):
        """Test retrieving high-risk threats"""
        # Insert various risk levels
        threats = [
            ThreatIntel(
                indicator=f"192.168.1.{i}",
                threat_type=ThreatType.IP,
                source_feeds=["test"],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                risk_score=risk,
                status=IntelStatus.ACTIVE,
                confidence=90,
                tags=[]
            )
            for i, risk in enumerate([95, 85, 75, 65, 55, 45, 35, 25, 15, 5])
        ]
        
        for threat in threats:
            self.db.upsert_threat_intel(threat)
        
        # Get high-risk (>=70)
        high_risk = self.db.get_high_risk_threats(min_risk_score=70)
        self.assertEqual(len(high_risk), 3)  # 95, 85, 75
        
        # Verify scores
        for threat in high_risk:
            self.assertGreaterEqual(threat.risk_score, 70)
    
    def test_get_active_indicators(self):
        """Test retrieving active indicators"""
        # Insert active and inactive
        active = ThreatIntel(
            indicator="192.168.1.1",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=85,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        
        inactive = ThreatIntel(
            indicator="192.168.1.2",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=85,
            status=IntelStatus.EXPIRED,
            confidence=90,
            tags=[]
        )
        
        self.db.upsert_threat_intel(active)
        self.db.upsert_threat_intel(inactive)
        
        active_indicators = self.db.get_active_indicators()
        self.assertEqual(len(active_indicators), 1)
        self.assertEqual(active_indicators[0].indicator, "192.168.1.1")
    
    def test_mark_as_false_positive(self):
        """Test marking indicator as false positive"""
        # Insert threat
        threat = ThreatIntel(
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=85,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        self.db.upsert_threat_intel(threat)
        
        # Mark as false positive
        result = self.db.mark_as_false_positive(
            "192.168.1.100", 
            "Test false positive", 
            "test_user"
        )
        self.assertTrue(result)
        
        # Verify status changed
        updated = self.db.db.threat_intel.find_one({"indicator": "192.168.1.100"})
        self.assertEqual(updated['status'], IntelStatus.FALSE_POSITIVE.value)
        self.assertEqual(updated['risk_score'], 0)
    
    def test_add_and_get_blocking_rules(self):
        """Test blocking rule operations"""
        rule = BlockingRule(
            rule_id="test_rule_001",
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            created_by="auto",
            reason="high_risk",
            risk_score=85
        )
        
        result = self.db.add_blocking_rule(rule)
        self.assertTrue(result)
        
        # Get active rules
        active_rules = self.db.get_active_blocking_rules()
        self.assertEqual(len(active_rules), 1)
        self.assertEqual(active_rules[0].indicator, "192.168.1.100")
    
    def test_remove_expired_rules(self):
        """Test expired rule cleanup"""
        # Active rule (not expired)
        active_rule = BlockingRule(
            rule_id="active_rule",
            indicator="192.168.1.1",
            threat_type=ThreatType.IP,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            created_by="auto",
            reason="test",
            risk_score=85
        )
        
        # Expired rule
        expired_rule = BlockingRule(
            rule_id="expired_rule",
            indicator="192.168.1.2",
            threat_type=ThreatType.IP,
            created_at=datetime.utcnow() - timedelta(days=2),
            expires_at=datetime.utcnow() - timedelta(hours=1),
            created_by="auto",
            reason="test",
            risk_score=85
        )
        
        self.db.add_blocking_rule(active_rule)
        self.db.add_blocking_rule(expired_rule)
        
        removed = self.db.remove_expired_rules()
        self.assertEqual(removed, 1)
        
        # Check active rules
        active_rules = self.db.get_active_blocking_rules()
        self.assertEqual(len(active_rules), 1)
        self.assertEqual(active_rules[0].indicator, "192.168.1.1")
    
    def test_audit_logging(self):
        """Test audit log operations"""
        audit = AuditLog(
            timestamp=datetime.utcnow(),
            action="test_action",
            indicator="192.168.1.100",
            user_or_system="test_user",
            details={"key": "value"}
        )
        
        result = self.db.log_audit(audit)
        self.assertTrue(result)
        
        # Retrieve logs
        logs = self.db.get_audit_logs(limit=10)
        self.assertGreaterEqual(len(logs), 1)
        self.assertEqual(logs[0].action, "test_action")
    
    def test_cleanup_old_data(self):
        """Test old data cleanup"""
        # Insert old threat
        old_threat = ThreatIntel(
            indicator="192.168.1.old",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow() - timedelta(days=100),
            last_seen=datetime.utcnow() - timedelta(days=100),
            risk_score=85,
            status=IntelStatus.EXPIRED,
            confidence=90,
            tags=[]
        )
        
        # Insert new threat
        new_threat = ThreatIntel(
            indicator="192.168.1.new",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=85,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        
        self.db.upsert_threat_intel(old_threat)
        self.db.upsert_threat_intel(new_threat)
        
        # Clean up data older than 90 days
        result = self.db.cleanup_old_data(days_to_keep=90)
        
        self.assertEqual(result['threats_removed'], 1)
        
        # Verify old threat is gone
        old_exists = self.db.db.threat_intel.find_one({"indicator": "192.168.1.old"})
        self.assertIsNone(old_exists)
    
    def test_record_hit(self):
        """Test recording block hits"""
        # Add a rule
        rule = BlockingRule(
            rule_id="hit_test_rule",
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            created_by="auto",
            reason="test",
            risk_score=85
        )
        self.db.add_blocking_rule(rule)
        
        # Add threat intel
        threat = ThreatIntel(
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            source_feeds=["test"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=85,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        self.db.upsert_threat_intel(threat)
        
        # Record a hit
        self.db.record_hit("192.168.1.100")
        
        # Verify hit count increased
        rule_updated = self.db.db.blocking_rules.find_one({"indicator": "192.168.1.100"})
        self.assertEqual(rule_updated['hit_count'], 1)
        
        threat_updated = self.db.db.threat_intel.find_one({"indicator": "192.168.1.100"})
        self.assertEqual(threat_updated['block_count'], 1)
    
    def tearDown(self):
        """Clean up after each test"""
        self.db.db.threat_intel.delete_many({})
        self.db.db.blocking_rules.delete_many({})
        self.db.db.audit_logs.delete_many({})
    
    @classmethod
    def tearDownClass(cls):
        """Drop test database"""
        cls.db.client.drop_database("test_threat_intel")


if __name__ == "__main__":
    unittest.main()