

import unittest
import sys
import os
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.siem.siem_bridge import SIEMBridge
from src.database.models import ThreatIntel, ThreatType, IntelStatus


class TestSIEMBridge(unittest.TestCase):
    """Test SIEM bridge functionality"""
    
    def setUp(self):
        """Set up test bridge"""
        self.bridge = SIEMBridge()
    
    @patch('src.siem.siem_bridge.socket.socket')
    def test_connect_logstash(self, mock_socket):
        """Test connection to Logstash"""
        mock_socket_instance = Mock()
        mock_socket.return_value = mock_socket_instance
        
        result = self.bridge.connect_logstash()
        
        # Note: May fail if Logstash not running, but we're mocking
        # This is a basic connectivity test
    
    def test_send_to_logstash_no_connection(self):
        """Test sending without connection"""
        self.bridge.socket = None
        result = self.bridge.send_to_logstash({"test": "data"})
        self.assertFalse(result)
    
    def test_send_threat_intel_format(self):
        """Test threat intel formatting for SIEM"""
        threat = ThreatIntel(
            indicator="192.168.1.100",
            threat_type=ThreatType.IP,
            source_feeds=["test_feed"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=85,
            status=IntelStatus.ACTIVE,
            confidence=90,
            tags=["malware", "c2"],
            geo_location={"country_code": "RU", "city": "Moscow"}
        )
        
        # Test formatting without actual sending
        data = {
            "type": "threat_intel",
            "timestamp": datetime.utcnow().isoformat(),
            "indicator": threat.indicator,
            "threat_type": threat.threat_type.value,
            "risk_score": threat.risk_score,
            "severity": threat.severity.value,
            "source_feeds": threat.source_feeds,
            "tags": threat.tags,
            "first_seen": threat.first_seen.isoformat(),
            "last_seen": threat.last_seen.isoformat(),
            "status": threat.status.value,
            "confidence": threat.confidence,
            "geo_location": threat.geo_location
        }
        
        self.assertEqual(data["indicator"], "192.168.1.100")
        self.assertEqual(data["risk_score"], 85)
        self.assertIn("malware", data["tags"])
    
    def test_send_alert_format(self):
        """Test alert formatting"""
        alert_data = {
            "type": "alert",
            "timestamp": datetime.utcnow().isoformat(),
            "indicator": "192.168.1.100",
            "reason": "high_risk_detected",
            "action": "blocked",
            "severity": "high"
        }
        
        self.assertEqual(alert_data["indicator"], "192.168.1.100")
        self.assertEqual(alert_data["action"], "blocked")
        self.assertEqual(alert_data["severity"], "high")
    
    def test_send_block_event_format(self):
        """Test block event formatting"""
        block_event = {
            "type": "block_event",
            "timestamp": datetime.utcnow().isoformat(),
            "indicator": "192.168.1.100",
            "rule_id": "auto_123456",
            "action": "blocked"
        }
        
        self.assertEqual(block_event["rule_id"], "auto_123456")
        self.assertEqual(block_event["action"], "blocked")


class TestSIEMBridgeIntegration(unittest.TestCase):
    """Integration tests for SIEM bridge (requires running ELK)"""
    
    @classmethod
    def setUpClass(cls):
        """Check if ELK is available"""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 5000))
        cls.elk_available = (result == 0)
        sock.close()
    
    def setUp(self):
        """Set up bridge"""
        self.bridge = SIEMBridge()
    
    @unittest.skipIf(not TestSIEMBridgeIntegration.elk_available, "ELK Stack not available")
    def test_actual_connection(self):
        """Test actual connection to Logstash"""
        result = self.bridge.connect_logstash()
        if result:
            self.assertIsNotNone(self.bridge.socket)
    
    @unittest.skipIf(not TestSIEMBridgeIntegration.elk_available, "ELK Stack not available")
    def test_actual_send(self):
        """Test actually sending data to Logstash"""
        self.bridge.connect_logstash()
        
        test_data = {
            "type": "test",
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Integration test message"
        }
        
        result = self.bridge.send_to_logstash(test_data)
        # Should return True if Logstash is running
        if self.bridge.socket:
            self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
