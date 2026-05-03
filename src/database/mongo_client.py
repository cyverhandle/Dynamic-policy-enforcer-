from pymongo import MongoClient, ASCENDING, DESCENDING, IndexModel, TEXT
from pymongo.errors import DuplicateKeyError, BulkWriteError
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import logging

from .models import ThreatIntel, ThreatType, IntelStatus, BlockingRule, AuditLog

logger = logging.getLogger(__name__)

class MongoDBClient:
    def __init__(self, connection_string: str, database_name: str):
        self.client = MongoClient(connection_string)
        self.db = self.client[database_name]
        self._setup_indexes()
    
    def _setup_indexes(self):
        """Create necessary indexes for performance"""
        # ThreatIntel collection indexes
        threat_intel_indexes = [
            IndexModel([("indicator", ASCENDING)], unique=True),
            IndexModel([("risk_score", DESCENDING)]),
            IndexModel([("last_seen", DESCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("severity", ASCENDING)]),
            IndexModel([("tags", ASCENDING)]),
            IndexModel([("first_seen", DESCENDING)]),
            IndexModel([("indicator", TEXT)], 
                       default_language="none")
        ]
        
        # BlockingRule collection indexes
        blocking_rule_indexes = [
            IndexModel([("indicator", ASCENDING)], unique=True),
            IndexModel([("expires_at", ASCENDING)]),
            IndexModel([("is_active", ASCENDING)]),
            IndexModel([("created_at", DESCENDING)])
        ]
        
        # AuditLog collection indexes
        audit_indexes = [
            IndexModel([("timestamp", DESCENDING)]),
            IndexModel([("action", ASCENDING)]),
            IndexModel([("user_or_system", ASCENDING)])
        ]
        
        try:
            self.db.threat_intel.create_indexes(threat_intel_indexes)
            self.db.blocking_rules.create_indexes(blocking_rule_indexes)
            self.db.audit_logs.create_indexes(audit_indexes)
            logger.info("Database indexes created successfully")
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
    
    # Threat Intelligence CRUD operations
    def upsert_threat_intel(self, threat: ThreatIntel) -> bool:
        """Insert or update threat intelligence"""
        try:
            result = self.db.threat_intel.update_one(
                {"indicator": threat.indicator},
                {"$set": threat.to_mongo()},
                upsert=True
            )
            return True
        except Exception as e:
            logger.error(f"Failed to upsert threat intel: {e}")
            return False
    
    def bulk_upsert_threat_intel(self, threats: List[ThreatIntel]) -> Dict[str, int]:
        """Bulk insert or update multiple threats"""
        if not threats:
            return {"inserted": 0, "updated": 0}
        
        operations = []
        for threat in threats:
            operations.append(
                pymongo.UpdateOne(
                    {"indicator": threat.indicator},
                    {"$set": threat.to_mongo()},
                    upsert=True
                )
            )
        
        try:
            result = self.db.threat_intel.bulk_write(operations, ordered=False)
            return {"inserted": result.upserted_count, "updated": result.modified_count}
        except BulkWriteError as e:
            logger.warning(f"Bulk write had partial errors: {e}")
            return {"inserted": e.details.get('nUpserted', 0), 
                    "updated": e.details.get('nModified', 0)}
    
    def get_high_risk_threats(self, min_risk_score: int = 70, 
                               limit: int = 1000) -> List[ThreatIntel]:
        """Get threats above risk threshold"""
        cursor = self.db.threat_intel.find({
            "risk_score": {"$gte": min_risk_score},
            "status": IntelStatus.ACTIVE.value
        }).sort("risk_score", DESCENDING).limit(limit)
        
        return [ThreatIntel.from_mongo(doc) for doc in cursor]
    
    def get_active_indicators(self, threat_type: ThreatType = None) -> List[ThreatIntel]:
        """Get all active threat indicators"""
        query = {"status": IntelStatus.ACTIVE.value}
        if threat_type:
            query["threat_type"] = threat_type.value
        
        cursor = self.db.threat_intel.find(query)
        return [ThreatIntel.from_mongo(doc) for doc in cursor]
    
    def mark_as_false_positive(self, indicator: str, comment: str, user: str) -> bool:
        """Mark an indicator as false positive"""
        try:
            self.db.threat_intel.update_one(
                {"indicator": indicator},
                {
                    "$set": {
                        "status": IntelStatus.FALSE_POSITIVE.value,
                        "risk_score": 0
                    },
                    "$push": {
                        "comments": {
                            "user": user,
                            "comment": comment,
                            "timestamp": datetime.utcnow()
                        }
                    }
                }
            )
            return True
        except Exception as e:
            logger.error(f"Failed to mark false positive: {e}")
            return False
    
    # Blocking Rule operations
    def add_blocking_rule(self, rule: BlockingRule) -> bool:
        """Add a new blocking rule"""
        try:
            self.db.blocking_rules.insert_one(rule.to_mongo())
            return True
        except DuplicateKeyError:
            logger.warning(f"Rule for {rule.indicator} already exists")
            return False
        except Exception as e:
            logger.error(f"Failed to add blocking rule: {e}")
            return False
    
    def get_active_blocking_rules(self) -> List[BlockingRule]:
        """Get all non-expired blocking rules"""
        cursor = self.db.blocking_rules.find({
            "is_active": True,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        return [BlockingRule(**doc) for doc in cursor]
    
    def remove_expired_rules(self) -> int:
        """Deactivate expired rules"""
        result = self.db.blocking_rules.update_many(
            {
                "is_active": True,
                "expires_at": {"$lte": datetime.utcnow()}
            },
            {"$set": {"is_active": False}}
        )
        return result.modified_count
    
    def record_hit(self, indicator: str) -> None:
        """Record that a blocked indicator was attempted"""
        self.db.blocking_rules.update_one(
            {"indicator": indicator},
            {
                "$inc": {"hit_count": 1},
                "$set": {"last_hit_at": datetime.utcnow()}
            }
        )
        
        # Also update threat intel
        self.db.threat_intel.update_one(
            {"indicator": indicator},
            {"$inc": {"block_count": 1}}
        )
    
    # Audit logging
    def log_audit(self, audit: AuditLog) -> bool:
        """Add an audit log entry"""
        try:
            self.db.audit_logs.insert_one(audit.to_mongo())
            return True
        except Exception as e:
            logger.error(f"Failed to log audit: {e}")
            return False
    
    def get_audit_logs(self, limit: int = 100, 
                       action: str = None) -> List[AuditLog]:
        """Retrieve audit logs"""
        query = {}
        if action:
            query["action"] = action
        
        cursor = self.db.audit_logs.find(query).sort("timestamp", DESCENDING).limit(limit)
        return [AuditLog(**doc) for doc in cursor]
    
    # Cleanup
    def cleanup_old_data(self, days_to_keep: int = 90) -> Dict[str, int]:
        """Remove old inactive data"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        # Remove old inactive threats
        threat_result = self.db.threat_intel.delete_many({
            "status": IntelStatus.EXPIRED.value,
            "last_seen": {"$lt": cutoff_date}
        })
        
        # Remove old audit logs
        audit_result = self.db.audit_logs.delete_many({
            "timestamp": {"$lt": cutoff_date}
        })
        
        return {
            "threats_removed": threat_result.deleted_count,
            "audit_logs_removed": audit_result.deleted_count
        }
