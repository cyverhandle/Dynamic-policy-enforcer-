

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import json
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.aggregators.base_aggregator import BaseAggregator
from src.aggregators.virustotal_aggregator import VirusTotalAggregator
from src.aggregators.alienvault_aggregator import AlienVaultAggregator
from src.aggregators.feodo_aggregator import FeodoAggregator
from src.aggregators.tor_aggregator import TorExitNodeAggregator
from src.database.models import ThreatIntel, ThreatType, IntelStatus


class TestBaseAggregator(unittest.TestCase):
    """Test base aggregator functionality"""
    
    def setUp(self):
        """Set up test aggregator"""
        class TestAggregator(BaseAggregator):
            def fetch_indicators(self):
                return ["192.168.1.1", "8.8.8.8"]
            
            def validate_indicator(self, indicator):
                return indicator.count('.') == 3
        
        self.aggregator = TestAggregator("test_feed", 75)
    
    def test_indicator_type_detection_ip(self):
        """Test IP address detection"""
        threat = self.aggregator.create_threat_intel("192.168.1.1")
        self.assertEqual(threat.threat_type, ThreatType.IP)
    
    def test_indicator_type_detection_domain(self):
        """Test domain detection"""
        threat = self.aggregator.create_threat_intel("malicious-domain.com")
        self.assertEqual(threat.threat_type, ThreatType.DOMAIN)
    
    def test_indicator_type_detection_url(self):
        """Test URL detection"""
        threat = self.aggregator.create_threat_intel("https://malicious.com/payload")
        self.assertEqual(threat.threat_type, ThreatType.URL)
    
    def test_indicator_type_detection_hash(self):
        """Test hash detection (MD5, SHA1, SHA256)"""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        threat_md5 = self.aggregator.create_threat_intel(md5_hash)
        threat_sha256 = self.aggregator.create_threat_intel(sha256_hash)
        
        self.assertEqual(threat_md5.threat_type, ThreatType.HASH)
        self.assertEqual(threat_sha256.threat_type, ThreatType.HASH)
    
    def test_risk_score_assignment(self):
        """Test risk score is properly assigned"""
        threat = self.aggregator.create_threat_intel("192.168.1.1")
        self.assertEqual(threat.risk_score, 75)
        self.assertIsNotNone(threat.severity)
    
    def test_source_tracking(self):
        """Test source feed is tracked"""
        threat = self.aggregator.create_threat_intel("192.168.1.1")
        self.assertIn("test_feed", threat.source_feeds)
    
    def test_timestamp_assignment(self):
        """Test timestamps are set"""
        threat = self.aggregator.create_threat_intel("192.168.1.1")
        self.assertIsNotNone(threat.first_seen)
        self.assertIsNotNone(threat.last_seen)
    
    def test_invalid_indicator_handling(self):
        """Test invalid indicators are rejected"""
        threat = self.aggregator.create_threat_intel("not_a_valid_indicator!!!")
        self.assertIsNone(threat)


class TestVirusTotalAggregator(unittest.TestCase):
    """Test VirusTotal aggregator"""
    
    @patch('src.aggregators.virustotal_aggregator.requests.Session.get')
    def test_fetch_indicators_with_api_key(self, mock_get):
        """Test fetching indicators with valid API key"""
        # Mock API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "id": "https://malicious.com",
                    "attributes": {
                        "url": "https://malicious.com",
                        "last_analysis_stats": {"malicious": 5, "harmless": 0}
                    }
                },
                {
                    "id": "185.130.5.253",
                    "attributes": {
                        "last_analysis_stats": {"malicious": 3, "harmless": 1}
                    }
                }
            ]
        }
        mock_get.return_value = mock_response
        
        aggregator = VirusTotalAggregator()
        # Mock API key exists
        aggregator.api_key = "test_api_key"
        
        indicators = aggregator.fetch_indicators()
        
        # Should return at least the indicators from mock
        self.assertIsInstance(indicators, list)
    
    def test_validate_indicator(self):
        """Test indicator validation"""
        aggregator = VirusTotalAggregator()
        
        valid_indicators = ["https://example.com", "185.130.5.253", "example.com"]
        invalid_indicators = ["", "a", "   "]
        
        for indicator in valid_indicators:
            self.assertTrue(aggregator.validate_indicator(indicator))
        
        for indicator in invalid_indicators:
            self.assertFalse(aggregator.validate_indicator(indicator))
    
    @patch('src.aggregators.virustotal_aggregator.requests.Session.get')
    def test_enrich_indicator(self, mock_get):
        """Test indicator enrichment"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 10, "total": 20},
                    "reputation": -50
                }
            }
        }
        mock_get.return_value = mock_response
        
        aggregator = VirusTotalAggregator()
        aggregator.api_key = "test_key"
        
        enrichment = aggregator.enrich_indicator("185.130.5.253")
        
        self.assertIn('tags', enrichment)
        self.assertIn('risk_modifier', enrichment)
        self.assertIsInstance(enrichment['tags'], list)


class TestAlienVaultAggregator(unittest.TestCase):
    """Test AlienVault OTX aggregator"""
    
    @patch('src.aggregators.alienvault_aggregator.requests.Session.get')
    def test_fetch_indicators(self, mock_get):
        """Test fetching from AlienVault"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "indicators": [
                        {"indicator": "192.168.1.100"},
                        {"indicator": "malware-domain.com"}
                    ]
                }
            ]
        }
        mock_get.return_value = mock_response
        
        aggregator = AlienVaultAggregator()
        aggregator.api_key = "test_key"
        
        indicators = aggregator.fetch_indicators()
        self.assertIsInstance(indicators, list)
    
    def test_validate_indicator(self):
        """Test validation logic"""
        aggregator = AlienVaultAggregator()
        
        # Valid indicators
        self.assertTrue(aggregator.validate_indicator("192.168.1.1"))
        self.assertTrue(aggregator.validate_indicator("example.com"))
        self.assertTrue(aggregator.validate_indicator("https://example.com/path"))
        
        # Invalid indicators
        self.assertFalse(aggregator.validate_indicator(""))
        self.assertFalse(aggregator.validate_indicator("a"))


class TestFeodoAggregator(unittest.TestCase):
    """Test Feodo Tracker aggregator"""
    
    @patch('src.aggregators.feodo_aggregator.requests.Session.get')
    def test_fetch_indicators(self, mock_get):
        """Test fetching Feodo Tracker data"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
# Feodo Tracker IP Blocklist
# Format: IP,First seen,Last seen,Status,AS,Country
185.130.5.253,2024-01-01,2024-01-15,online,AS12345,RU
45.142.211.155,2024-01-02,2024-01-16,online,AS67890,CN
"""
        mock_get.return_value = mock_response
        
        aggregator = FeodoAggregator()
        indicators = aggregator.fetch_indicators()
        
        self.assertEqual(len(indicators), 2)
        self.assertIn("185.130.5.253", indicators)
        self.assertIn("45.142.211.155", indicators)
    
    def test_validate_indicator_ip(self):
        """Test IP validation"""
        aggregator = FeodoAggregator()
        
        # Valid IPs
        self.assertTrue(aggregator.validate_indicator("192.168.1.1"))
        self.assertTrue(aggregator.validate_indicator("8.8.8.8"))
        self.assertTrue(aggregator.validate_indicator("0.0.0.0"))
        
        # Invalid IPs
        self.assertFalse(aggregator.validate_indicator("256.1.1.1"))
        self.assertFalse(aggregator.validate_indicator("192.168.1"))
        self.assertFalse(aggregator.validate_indicator("not_an_ip"))
    
    def test_enrich_indicator(self):
        """Test enrichment for Feodo indicators"""
        aggregator = FeodoAggregator()
        enrichment = aggregator.enrich_indicator("185.130.5.253")
        
        self.assertIn('c2_server', enrichment['tags'])
        self.assertEqual(enrichment['risk_modifier'], 5)


class TestTorExitNodeAggregator(unittest.TestCase):
    """Test Tor exit node aggregator"""
    
    @patch('src.aggregators.tor_aggregator.requests.Session.get')
    def test_fetch_indicators(self, mock_get):
        """Test fetching Tor exit nodes"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "185.130.5.253\n45.142.211.155\n94.142.241.25"
        mock_get.return_value = mock_response
        
        aggregator = TorExitNodeAggregator()
        indicators = aggregator.fetch_indicators()
        
        self.assertGreaterEqual(len(indicators), 1)
    
    def test_validate_indicator(self):
        """Test IP validation"""
        aggregator = TorExitNodeAggregator()
        
        self.assertTrue(aggregator.validate_indicator("192.168.1.1"))
        self.assertFalse(aggregator.validate_indicator("invalid"))


if __name__ == "__main__":
    unittest.main()