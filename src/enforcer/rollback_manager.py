"""
Rollback Manager for False Positives
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from ..database.mongo_client import MongoDBClient
from ..database.models import AuditLog, ThreatIntel, IntelStatus
from .policy_enforcer import FirewallEnforcer

logger = logging.getLogger(__name__)

class RollbackManager:
    """Manages rollback of automated policies"""
    
    def __init__(self, enforcer: FirewallEnforcer):
        self.enforcer = enforcer
        self.db = enforcer.db
        self.rollback_window_hours = 24  # Can rollback rules from last 24 hours
    
    def rollback_rule(self, indicator: str, reason: str = "false_positive") -> bool:
        """Rollback a specific blocking rule"""
        success = self.enforcer.manual_unblock(indicator, reason)
        
        if success:
            # Mark as false positive in threat intel
            self.db.mark_as_false_positive(indicator, reason, "rollback_manager")
            
            # Add to whitelist to prevent re-blocking
            self._add_to_whitelist(indicator, reason)
            
            logger.info(f"Rolled back block for {indicator}: {reason}")
            return True
        
        return False
    
    def rollback_recent_rules(self, minutes: int = 60) -> int:
        """Rollback all rules created in the last X minutes"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        recent_rules = self.db.db.blocking_rules.find({
            "created_at": {"$gte": cutoff_time},
            "is_active": True,
            "created_by": "auto"
        })
        
        rolled_back = 0
        for rule in recent_rules:
            if self.rollback_rule(rule['indicator'], f"batch_rollback_{minutes}m"):
                rolled_back += 1
        
        logger.info(f"Rolled back {rolled_back} rules from last {minutes} minutes")
        return rolled_back
    
    def investigate_and_rollback(self, indicator: str, analyst: str) -> Dict[str, Any]:
        """Investigate a potential false positive and rollback if confirmed"""
        result = {
            "indicator": indicator,
            "action": None,
            "reason": None
        }
        
        # Get threat intelligence for this indicator
        threat = self.db.db.threat_intel.find_one({"indicator": indicator})
        
        if not threat:
            result["action"] = "not_found"
            result["reason"] = "Indicator not found in threat database"
            return result
        
        # Check if it's already marked as false positive
        if threat.get('status') == IntelStatus.FALSE_POSITIVE.value:
            result["action"] = "already_cleared"
            result["reason"] = "Already marked as false positive"
            return result
        
        # Check confidence and source count
        confidence = threat.get('confidence', 0)
        source_count = len(threat.get('source_feeds', []))
        
        # Low confidence and single source suggests possible false positive
        if confidence < 50 and source_count == 1:
            self.rollback_rule(indicator, f"investigation_by_{analyst}_low_confidence")
            result["action"] = "rolled_back"
            result["reason"] = "Low confidence and single source"
        else:
            # Log that analyst wants to investigate further
            result["action"] = "requires_further_investigation"
            result["reason"] = f"Multiple sources ({source_count}) or high confidence ({confidence})"
            
            # Add comment to threat
            self.db.db.threat_intel.update_one(
                {"indicator": indicator},
                {"$push": {
                    "comments": {
                        "user": analyst,
                        "comment": "Under investigation for potential false positive",
                        "timestamp": datetime.utcnow()
                    }
                }}
            )
        
        return result
    
    def _add_to_whitelist(self, indicator: str, reason: str):
        """Add indicator to whitelist to prevent future auto-blocking"""
        whitelist_collection = self.db.db.whitelist
        whitelist_collection.update_one(
            {"indicator": indicator},
            {
                "$set": {
                    "indicator": indicator,
                    "added_at": datetime.utcnow(),
                    "reason": reason,
                    "type": "false_positive"
                }
            },
            upsert=True
        )
        logger.info(f"Added {indicator} to whitelist")
    
    def get_rollback_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get history of rollback actions"""
        audit_logs = self.db.get_audit_logs(
            limit=limit,
            action="manual_unblock"
        )
        
        return [
            {
                "timestamp": log.timestamp.isoformat(),
                "indicator": log.indicator,
                "reason": log.details.get('reason', 'unknown'),
                "user": log.user_or_system
            }
            for log in audit_logs
        ]
    
    def simulate_rollback(self, indicator: str) -> Dict[str, Any]:
        """Simulate rollback to see what would happen"""
        threat = self.db.db.threat_intel.find_one({"indicator": indicator})
        
        if not threat:
            return {"can_rollback": False, "reason": "No threat data found"}
        
        is_blocked = self.db.db.blocking_rules.find_one({
            "indicator": indicator,
            "is_active": True
        }) is not None
        
        if not is_blocked:
            return {"can_rollback": False, "reason": "Indicator is not currently blocked"}
        
        # Check if we have high confidence it's malicious
        if threat.get('risk_score', 0) >= 90 and len(threat.get('source_feeds', [])) >= 3:
            return {
                "can_rollback": False,
                "reason": "High confidence malicious indicator from multiple sources",
                "risk_score": threat.get('risk_score'),
                "sources": threat.get('source_feeds')
            }
        
        return {
            "can_rollback": True,
            "reason": "Low to medium confidence indicator",
            "risk_score": threat.get('risk_score', 0),
            "sources": threat.get('source_feeds', [])
        }