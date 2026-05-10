#!/usr/bin/env python3
"""
Test AbuseIPDB Aggregator
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.aggregators.abuseipdb_aggregator import AbuseIPDBAggregator

def test_abuseipdb():
    """Test AbuseIPDB integration"""
    
    # Initialize aggregator
    aggregator = AbuseIPDBAggregator()
    
    if not aggregator.enabled:
        print("❌ AbuseIPDB API key not configured")
        print("Add ABUSEIPDB_API_KEY to .env file")
        return
    
    print("✓ AbuseIPDB aggregator initialized")
    
    # Test fetching indicators
    print("\n📡 Fetching malicious IPs...")
    indicators = aggregator.fetch_indicators()
    print(f"✓ Found {len(indicators)} malicious IPs")
    
    if indicators:
        # Test first IP enrichment
        test_ip = indicators[0]
        print(f"\n🔍 Testing enrichment for {test_ip}...")
        
        threat = aggregator.create_threat_intel(test_ip)
        if threat:
            print(f"  Risk Score: {threat.risk_score}")
            print(f"  Confidence: {threat.confidence}")
            print(f"  Tags: {', '.join(threat.tags)}")
            if threat.geo_location:
                print(f"  Location: {threat.geo_location.get('country_name')}")
    
    print("\n✅ AbuseIPDB integration test complete!")

if __name__ == "__main__":
    test_abuseipdb()
