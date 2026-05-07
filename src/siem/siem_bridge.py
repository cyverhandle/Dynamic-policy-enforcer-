
import json
import logging
import socket
import threading
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from queue import Queue, Empty

import pymongo
from pymongo import MongoClient
from pymongo.cursor import CursorType

from ..config.settings import config
from ..database.models import ThreatIntel, ThreatSeverity

logger = logging.getLogger(__name__)


class SIEMBridge:
    """Bridge between MongoDB and ELK Stack for real-time threat visualization"""
    
    def __init__(self):
        self.mongo_client = MongoClient(config.database.mongodb_uri)
        self.db = self.mongo_client[config.database.mongodb_db]
        
        # Logstash connection settings
        self.logstash_host = os.getenv("LOGSTASH_HOST", "localhost")
        self.logstash_port = int(os.getenv("LOGSTASH_PORT", 5000))
        self.socket = None
        self.socket_lock = threading.Lock()
        
        # Queue for batched sending
        self.send_queue = Queue(maxsize=10000)
        self.batch_size = 100
        self.batch_timeout = 5  # seconds
        
        # Sync state
        self.running = False
        self.sync_thread = None
        self.batch_thread = None
        self.last_sync_time = datetime.utcnow() - timedelta(hours=24)
        
        # Statistics
        self.stats = {
            "events_sent": 0,
            "batch_count": 0,
            "errors": 0,
            "last_success": None
        }
    
    def connect_logstash(self) -> bool:
        """Establish connection to Logstash TCP input"""
        with self.socket_lock:
            if self.socket:
                return True
            
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((self.logstash_host, self.logstash_port))
                logger.info(f"Connected to Logstash at {self.logstash_host}:{self.logstash_port}")
                return True
            except Exception as e:
                logger.error(f"Failed to connect to Logstash: {e}")
                self.socket = None
                return False
    
    def disconnect_logstash(self):
        """Close Logstash connection"""
        with self.socket_lock:
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None
                logger.info("Disconnected from Logstash")
    
    def send_to_logstash(self, data: Dict[str, Any]) -> bool:
        """Send single event to Logstash via TCP"""
        if not self.connect_logstash():
            return False
        
        try:
            message = json.dumps(data) + "\n"
            with self.socket_lock:
                self.socket.send(message.encode('utf-8'))
            self.stats["events_sent"] += 1
            self.stats["last_success"] = datetime.utcnow()
            return True
        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            logger.error(f"Socket error sending to Logstash: {e}")
            self.disconnect_logstash()
            self.stats["errors"] += 1
            return False
        except Exception as e:
            logger.error(f"Error sending to Logstash: {e}")
            self.stats["errors"] += 1
            return False
    
    def send_batch(self, events: List[Dict[str, Any]]) -> int:
        """Send batch of events to Logstash"""
        if not events:
            return 0
        
        # Convert to newline-delimited JSON
        payload = "\n".join(json.dumps(event) for event in events) + "\n"
        
        if not self.connect_logstash():
            return 0
        
        try:
            with self.socket_lock:
                self.socket.send(payload.encode('utf-8'))
            
            self.stats["events_sent"] += len(events)
            self.stats["batch_count"] += 1
            self.stats["last_success"] = datetime.utcnow()
            logger.debug(f"Sent batch of {len(events)} events to Logstash")
            return len(events)
        except Exception as e:
            logger.error(f"Failed to send batch: {e}")
            self.disconnect_logstash()
            self.stats["errors"] += 1
            return 0
    
    def queue_event(self, event: Dict[str, Any]):
        """Queue an event for batch processing"""
        try:
            self.send_queue.put_nowait(event)
        except Queue.Full:
            logger.warning("Send queue full, dropping event")
    
    def format_threat_event(self, threat: ThreatIntel) -> Dict[str, Any]:
        """Format threat intelligence for Elasticsearch"""
        return {
            "@timestamp": datetime.utcnow().isoformat(),
            "type": "threat_intel",
            "indicator": {
                "value": threat.indicator,
                "type": threat.threat_type.value
            },
            "risk": {
                "score": threat.risk_score,
                "level": threat.severity.value if threat.severity else "unknown",
                "level_numeric": self._severity_to_numeric(threat.severity)
            },
            "sources": {
                "feeds": threat.source_feeds,
                "count": len(threat.source_feeds)
            },
            "temporal": {
                "first_seen": threat.first_seen.isoformat(),
                "last_seen": threat.last_seen.isoformat(),
                "age_hours": (datetime.utcnow() - threat.first_seen).total_seconds() / 3600
            },
            "confidence": threat.confidence,
            "tags": threat.tags,
            "geo": threat.geo_location,
            "status": threat.status.value,
            "context": {
                "block_count": threat.block_count,
                "related_indicators": threat.related_indicators[:5] if threat.related_indicators else []
            }
        }
    
    def _severity_to_numeric(self, severity: ThreatSeverity) -> int:
        """Convert severity enum to numeric value"""
        if not severity:
            return 0
        mapping = {
            ThreatSeverity.CRITICAL: 4,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 1
        }
        return mapping.get(severity, 0)
    
    def format_alert_event(self, indicator: str, reason: str, action: str, 
                           risk_score: int) -> Dict[str, Any]:
        """Format alert event for Elasticsearch"""
        return {
            "@timestamp": datetime.utcnow().isoformat(),
            "type": "security_alert",
            "indicator": indicator,
            "alert": {
                "reason": reason,
                "action": action,
                "risk_score": risk_score,
                "severity": self._get_alert_severity(risk_score)
            }
        }
    
    def _get_alert_severity(self, risk_score: int) -> str:
        """Get alert severity based on risk score"""
        if risk_score >= 90:
            return "critical"
        elif risk_score >= 70:
            return "high"
        elif risk_score >= 40:
            return "medium"
        else:
            return "low"
    
    def format_block_event(self, indicator: str, rule_id: str, 
                           action: str) -> Dict[str, Any]:
        """Format firewall block event for Elasticsearch"""
        return {
            "@timestamp": datetime.utcnow().isoformat(),
            "type": "firewall_event",
            "indicator": indicator,
            "firewall": {
                "rule_id": rule_id,
                "action": action,
                "status": "applied"
            }
        }
    
    def sync_new_threats(self) -> int:
        """Synchronize new threats to SIEM"""
        # Find threats that haven't been synced
        new_threats_cursor = self.db.threat_intel.find({
            "first_seen": {"$gt": self.last_sync_time},
            "synced_to_siem": {"$ne": True}
        }).limit(500)
        
        events = []
        for threat_doc in new_threats_cursor:
            threat = ThreatIntel.from_mongo(threat_doc)
            event = self.format_threat_event(threat)
            events.append(event)
            
            # Mark as synced
            self.db.threat_intel.update_one(
                {"_id": threat_doc["_id"]},
                {"$set": {"synced_to_siem": True, "synced_at": datetime.utcnow()}}
            )
        
        if events:
            sent = self.send_batch(events)
            logger.info(f"Synced {sent} new threats to SIEM")
            return sent
        
        return 0
    
    def sync_high_risk_threats(self) -> int:
        """Synchronize high-risk threats to SIEM (priority)"""
        high_risk_cursor = self.db.threat_intel.find({
            "risk_score": {"$gte": 70},
            "status": "active",
            "high_risk_synced": {"$ne": True}
        }).limit(100)
        
        events = []
        for threat_doc in high_risk_cursor:
            threat = ThreatIntel.from_mongo(threat_doc)
            event = self.format_threat_event(threat)
            # Add priority flag
            event["priority"] = "high"
            events.append(event)
            
            self.db.threat_intel.update_one(
                {"_id": threat_doc["_id"]},
                {"$set": {"high_risk_synced": True}}
            )
        
        if events:
            sent = self.send_batch(events)
            logger.warning(f"Synced {sent} HIGH RISK threats to SIEM")
            return sent
        
        return 0
    
    def batch_processor(self):
        """Background thread for batch processing"""
        batch = []
        last_batch_time = datetime.utcnow()
        
        while self.running:
            try:
                # Get event from queue with timeout
                try:
                    event = self.send_queue.get(timeout=1)
                    batch.append(event)
                except Empty:
                    pass
                
                # Send batch if size or time threshold reached
                now = datetime.utcnow()
                should_send = (
                    len(batch) >= self.batch_size or
                    (batch and (now - last_batch_time).total_seconds() >= self.batch_timeout)
                )
                
                if should_send and batch:
                    self.send_batch(batch)
                    batch = []
                    last_batch_time = now
                
            except Exception as e:
                logger.error(f"Batch processor error: {e}")
                time.sleep(1)
        
        # Send remaining events on shutdown
        if batch:
            self.send_batch(batch)
    
    def continuous_sync(self, interval_seconds: int = 60):
        """Continuously sync data to SIEM"""
        while self.running:
            try:
                # Priority: sync high-risk threats first
                self.sync_high_risk_threats()
                
                # Then sync new threats
                self.sync_new_threats()
                
                # Update last sync time (rolling window)
                self.last_sync_time = datetime.utcnow() - timedelta(minutes=5)
                
                # Log statistics periodically
                if int(time.time()) % 300 < 10:  # Every ~5 minutes
                    logger.info(f"SIEM Bridge Stats: {self.stats}")
                
                time.sleep(interval_seconds)
                
            except Exception as e:
                logger.error(f"Error in continuous sync: {e}")
                time.sleep(10)
    
    def send_test_event(self) -> bool:
        """Send a test event to verify SIEM connectivity"""
        test_event = {
            "@timestamp": datetime.utcnow().isoformat(),
            "type": "test",
            "message": "SIEM Bridge connectivity test",
            "source": "Threat Intelligence Platform"
        }
        return self.send_to_logstash(test_event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bridge statistics"""
        return {
            **self.stats,
            "queue_size": self.send_queue.qsize(),
            "connected": self.socket is not None,
            "last_sync": self.last_sync_time.isoformat()
        }
    
    def start(self):
        """Start the SIEM bridge"""
        self.running = True
        
        # Start batch processor thread
        self.batch_thread = threading.Thread(
            target=self.batch_processor,
            name="SIEM-BatchProcessor",
            daemon=True
        )
        self.batch_thread.start()
        
        # Start sync thread
        self.sync_thread = threading.Thread(
            target=self.continuous_sync,
            name="SIEM-ContinuousSync",
            daemon=True
        )
        self.sync_thread.start()
        
        logger.info("SIEM Bridge started")
        
        # Send test event on startup
        if self.send_test_event():
            logger.info("SIEM connectivity test successful")
        else:
            logger.warning("SIEM connectivity test failed - check Logstash")
    
    def stop(self):
        """Stop the SIEM bridge gracefully"""
        logger.info("Stopping SIEM Bridge...")
        self.running = False
        
        if self.sync_thread:
            self.sync_thread.join(timeout=10)
        if self.batch_thread:
            self.batch_thread.join(timeout=10)
        
        self.disconnect_logstash()
        logger.info("SIEM Bridge stopped")