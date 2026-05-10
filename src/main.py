#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform - Main Orchestrator
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime
from typing import List
import threading
import time

from config.settings import config
from database.mongo_client import MongoDBClient
from database.models import ThreatIntel, AuditLog, BlockingRule
from aggregators.virustotal_aggregator import VirusTotalAggregator
from aggregators.alienvault_aggregator import AlienVaultAggregator
from aggregators.abuseipdb_aggregator import AbuseIPDBAggregator  
from aggregators.feodo_aggregator import FeodoAggregator
from aggregators.tor_aggregator import TorExitNodeAggregator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_intel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatIntelligencePlatform:
    """Main orchestration class for TIP"""
    
    def __init__(self):
        self.db = MongoDBClient(
            config.database.mongodb_uri,
            config.database.mongodb_db
        )
        self.aggregators = [
            VirusTotalAggregator(),
            AlienVaultAggregator(),
            AbuseIPDBAggregator(), 
            FeodoAggregator(),
            TorExitNodeAggregator()
        ]
        self.running = False
        self.collection_thread = None
    
    def collect_all_feeds(self) -> int:
        """Collect from all enabled threat feeds"""
        total_indicators = 0
        
        for aggregator in self.aggregators:
            if aggregator.enabled:
                logger.info(f"Starting collection from {aggregator.name}")
                threats = aggregator.collect()
                
                if threats:
                    result = self.db.bulk_upsert_threat_intel(threats)
                    total_indicators += result['inserted'] + result['updated']
                    logger.info(
                        f"Feed {aggregator.name}: {result['inserted']} new, "
                        f"{result['updated']} updated"
                    )
                    
                    # Log audit
                    audit = AuditLog(
                        timestamp=datetime.utcnow(),
                        action="feed_collection",
                        indicator="",
                        user_or_system="system",
                        details={
                            "feed": aggregator.name,
                            "new_indicators": result['inserted'],
                            "updated_indicators": result['updated']
                        }
                    )
                    self.db.log_audit(audit)
        
        return total_indicators
    
    def continuous_collection(self, interval_seconds: int = 1800):
        """Run collection in a loop for continuous updates"""
        logger.info(f"Starting continuous collection every {interval_seconds} seconds")
        
        while self.running:
            try:
                start_time = time.time()
                total = self.collect_all_feeds()
                elapsed = time.time() - start_time
                
                logger.info(f"Collection cycle complete: {total} indicators processed in {elapsed:.2f}s")
                
                # Clean up old data daily
                if datetime.utcnow().hour == 0 and datetime.utcnow().minute < 5:
                    cleanup_result = self.db.cleanup_old_data(days_to_keep=90)
                    logger.info(f"Cleanup completed: {cleanup_result}")
                
                # Sleep for the interval
                time.sleep(max(0, interval_seconds - elapsed))
                
            except Exception as e:
                logger.error(f"Error in collection cycle: {e}")
                time.sleep(60)  # Sleep and retry
    
    def start(self):
        """Start the threat intelligence platform"""
        self.running = True
        logger.info("Starting Threat Intelligence Platform")
        
        # Initial collection
        logger.info("Performing initial feed collection...")
        self.collect_all_feeds()
        
        # Start continuous collection thread
        self.collection_thread = threading.Thread(
            target=self.continuous_collection,
            args=(1800,),  # 30 minutes
            daemon=True
        )
        self.collection_thread.start()
        
        logger.info("Threat Intelligence Platform is running")
        
        # Wait for shutdown signal
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        
        while self.running:
            time.sleep(1)
    
    def stop(self, signum=None, frame=None):
        """Stop the platform gracefully"""
        logger.info("Shutting down Threat Intelligence Platform...")
        self.running = False
        
        if self.collection_thread:
            self.collection_thread.join(timeout=30)
        
        logger.info("Shutdown complete")

def main():
    """Entry point"""
    platform = ThreatIntelligencePlatform()
    
    # Validate configuration
    if not config.database.mongodb_uri:
        logger.error("MongoDB URI not configured!")
        sys.exit(1)
    
    try:
        platform.start()
    except KeyboardInterrupt:
        platform.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
