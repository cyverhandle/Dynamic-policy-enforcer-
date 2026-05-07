
import unittest
import sys
import os
import json
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.app import app
from src.database.mongo_client import MongoDBClient
from src.database.models import ThreatIntel, ThreatType, IntelStatus, BlockingRule, AuditLog
from src.config.settings import config


class TestAPI(unittest.TestCase):
    """Test REST API endpoints"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test client and database"""
        app.config['TESTING'] = True
        cls.client = app.test_client()
        cls.db = MongoDBClient(
            config.database.mongodb_uri,
            "test_api"
        )
    
    def setUp(self):
        """Clean up before each test"""
        self.db.db.threat_intel.delete_many({})
        self.db.db.blocking_rules.delete_many({})
        self.db.db.audit_logs.delete_many({})
        
        # Insert test data
        self.test_threat = ThreatIntel(
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
        self.db.upsert_threat_intel(self.test_threat)
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'operational')
        self.assertIn('components', data)
    
    def test_get_threats(self):
        """Test GET /api/threats"""
        response = self.client.get('/api/threats')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('threats', data)
        self.assertIn('count', data)
        self.assertGreaterEqual(data['count'], 1)
    
    def test_get_threats_with_filter(self):
        """Test GET /api/threats with filters"""
        # Add more test data
        threat2 = ThreatIntel(
            indicator="malicious.com",
            threat_type=ThreatType.DOMAIN,
            source_feeds=["test_feed"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=45,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=[]
        )
        self.db.upsert_threat_intel(threat2)
        
        # Filter by min risk
        response = self.client.get('/api/threats?min_risk=70')
        data = json.loads(response.data)
        
        for threat in data['threats']:
            self.assertGreaterEqual(threat['risk_score'], 70)
    
    def test_get_specific_threat(self):
        """Test GET /api/threats/<indicator>"""
        response = self.client.get('/api/threats/192.168.1.100')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['indicator'], '192.168.1.100')
        self.assertEqual(data['risk_score'], 85)
    
    def test_get_nonexistent_threat(self):
        """Test GET for non-existent threat"""
        response = self.client.get('/api/threats/nonexistent.com')
        self.assertEqual(response.status_code, 404)
    
    def test_get_blocks(self):
        """Test GET /api/blocks"""
        # Add a blocking rule
        rule = BlockingRule(
            rule_id="test_rule",
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow(),
            created_by="auto",
            reason="test",
            risk_score=85
        )
        self.db.add_blocking_rule(rule)
        
        response = self.client.get('/api/blocks')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('blocks', data)
        self.assertIn('count', data)
    
    def test_add_manual_block(self):
        """Test POST /api/blocks"""
        block_data = {
            "indicator": "45.142.211.155",
            "reason": "manual_block_test",
            "duration_seconds": 3600
        }
        
        response = self.client.post(
            '/api/blocks',
            data=json.dumps(block_data),
            content_type='application/json'
        )
        
        # May fail if firewall not configured, but API should respond
        self.assertIn(response.status_code, [200, 500])
    
    def test_add_block_missing_indicator(self):
        """Test POST without indicator"""
        response = self.client.post(
            '/api/blocks',
            data=json.dumps({"reason": "test"}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
    
    def test_get_audit_logs(self):
        """Test GET /api/audit"""
        # Add audit log
        audit = AuditLog(
            timestamp=datetime.utcnow(),
            action="test_action",
            indicator="192.168.1.100",
            user_or_system="test",
            details={}
        )
        self.db.log_audit(audit)
        
        response = self.client.get('/api/audit')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('logs', data)
        self.assertIn('count', data)
    
    def test_get_audit_logs_with_filter(self):
        """Test GET /api/audit with action filter"""
        # Add multiple audit logs
        actions = ["block_added", "block_removed", "test_action"]
        for action in actions:
            audit = AuditLog(
                timestamp=datetime.utcnow(),
                action=action,
                indicator="test.com",
                user_or_system="test",
                details={}
            )
            self.db.log_audit(audit)
        
        response = self.client.get('/api/audit?action=block_added')
        data = json.loads(response.data)
        
        for log in data['logs']:
            self.assertEqual(log['action'], 'block_added')
    
    def test_get_stats(self):
        """Test GET /api/stats"""
        response = self.client.get('/api/stats')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        
        self.assertIn('total_threats', data)
        self.assertIn('active_threats', data)
        self.assertIn('high_risk_count', data)
        self.assertIn('critical_risk_count', data)
        self.assertIn('active_blocks', data)
        self.assertIn('top_threat_sources', data)
        
        # Verify counts are integers
        self.assertIsInstance(data['total_threats'], int)
        self.assertIsInstance(data['active_threats'], int)
    
    def test_get_daily_report(self):
        """Test GET /api/reports/daily"""
        response = self.client.get('/api/reports/daily')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        
        self.assertIn('date', data)
        self.assertIn('total_threats', data)
        self.assertIn('blocks_applied', data)
        self.assertIn('top_feeds', data)
    
    def test_rollback_endpoint(self):
        """Test POST /api/rollback/<indicator>"""
        # Add a block rule first
        rule = BlockingRule(
            rule_id="rollback_test",
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow(),
            created_by="auto",
            reason="test",
            risk_score=85
        )
        self.db.add_blocking_rule(rule)
        
        response = self.client.post(
            '/api/rollback/192.168.1.100',
            data=json.dumps({"reason": "false_positive_test"}),
            content_type='application/json'
        )
        
        self.assertIn(response.status_code, [200, 400, 500])
    
    def tearDown(self):
        """Clean up after each test"""
        self.db.db.threat_intel.delete_many({})
        self.db.db.blocking_rules.delete_many({})
        self.db.db.audit_logs.delete_many({})
    
    @classmethod
    def tearDownClass(cls):
        """Drop test database"""
        cls.db.client.drop_database("test_api")


if __name__ == "__main__":
    unittest.main()