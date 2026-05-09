#!/usr/bin/env python3
"""
Dynamic Security Policy Enforcer - Automatically blocks high-risk threats
"""

import subprocess
import logging
import threading
import time
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from ipaddress import ip_address, ip_network

import redis

from ..config.settings import config
from ..database.mongo_client import MongoDBClient
from ..database.models import ThreatIntel, BlockingRule, ThreatType, IntelStatus, AuditLog
from ..siem.siem_bridge import SIEMBridge

logger = logging.getLogger(__name__)

class FirewallEnforcer:
    """Manages dynamic firewall rules based on threat intelligence"""
    
    def __init__(self):
        self.db = MongoDBClient(
            config.database.mongodb_uri,
            config.database.mongodb_db
        )
        self.redis_client = redis.Redis(
            host=config.database.redis_host,
            port=config.database.redis_port,
            db=config.database.redis_db,
            decode_responses=True
        )
        self.siem = SIEMBridge()
        
        self.firewall_type = config.enforcement.firewall_type
        self.block_duration = config.enforcement.block_duration_seconds
        self.high_risk_threshold = config.enforcement.high_risk_threshold
        self.auto_block_enabled = config.enforcement.auto_block_enabled
        
        self.running = False
        self.monitor_thread = None
        self.cleanup_thread = None
        
        # Track active blocks in Redis for fast lookup
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis with existing rules"""
        # Load existing active rules into Redis cache
        active_rules = self.db.get_active_blocking_rules()
        for rule in active_rules:
            key = f"block:{rule.indicator}"
            self.redis_client.setex(key, self.block_duration, rule.rule_id)
        logger.info(f"Loaded {len(active_rules)} active rules into Redis")
    
    def _execute_iptables_command(self, action: str, ip: str, chain: str = "INPUT") -> bool:
        """Execute iptables command to add or remove rule"""
        try:
            if action == "add":
                cmd = ["iptables", "-A", chain, "-s", ip, "-j", "DROP"]
            elif action == "remove":
                cmd = ["iptables", "-D", chain, "-s", ip, "-j", "DROP"]
            else:
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"iptables: {action} {ip} to {chain}")
                return True
            else:
                logger.error(f"iptables error: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to execute iptables command: {e}")
            return False
    
    def _execute_nftables_command(self, action: str, ip: str) -> bool:
        """Execute nftables command for newer Linux systems"""
        try:
            if action == "add":
                cmd = ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"]
            elif action == "remove":
                # Need to find handle first - simplified version
                cmd = ["nft", "delete", "rule", "inet", "filter", "input", "handle", self._find_nft_handle(ip)]
            else:
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Failed to execute nftables command: {e}")
            return False
    
    def _find_nft_handle(self, ip: str) -> str:
        """Find nftables rule handle for a given IP"""
        try:
            result = subprocess.run(
                ["nft", "-a", "list", "chain", "inet", "filter", "input"],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split('\n'):
                if ip in line and "drop" in line:
                    # Extract handle number
                    import re
                    match = re.search(r'handle (\d+)', line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return ""
    
    def add_block_rule(self, threat: ThreatIntel, reason: str = "auto") -> Optional[BlockingRule]:
        """Add a block rule for a threat indicator"""
        if not self.auto_block_enabled:
            logger.info("Auto-blocking disabled, skipping rule addition")
            return None
        
        # Only block IPs and CIDRs for now
        if threat.threat_type not in [ThreatType.IP, ThreatType.CIDR]:
            logger.debug(f"Skipping non-IP indicator: {threat.indicator}")
            return None
        
        # Check if already blocked
        if self.redis_client.exists(f"block:{threat.indicator}"):
            logger.debug(f"Indicator already blocked: {threat.indicator}")
            return None
        
        # Create blocking rule
        rule = BlockingRule(
            rule_id=f"auto_{int(datetime.utcnow().timestamp())}_{threat.indicator.replace('.', '_')}",
            indicator=threat.indicator,
            threat_type=threat.threat_type,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=self.block_duration),
            created_by="auto",
            reason=reason,
            risk_score=threat.risk_score
        )
        
        # Apply firewall rule
        success = False
        if self.firewall_type == "iptables":
            success = self._execute_iptables_command("add", threat.indicator)
        elif self.firewall_type == "nftables":
            success = self._execute_nftables_command("add", threat.indicator)
        
        if success:
            # Save rule to database
            self.db.add_blocking_rule(rule)
            
            # Cache in Redis
            self.redis_client.setex(f"block:{threat.indicator}", self.block_duration, rule.rule_id)
            
            # Log audit
            audit = AuditLog(
                timestamp=datetime.utcnow(),
                action="block_added",
                indicator=threat.indicator,
                user_or_system="auto",
                details={
                    "rule_id": rule.rule_id,
                    "risk_score": threat.risk_score,
                    "reason": reason
                }
            )
            self.db.log_audit(audit)
            
            # Send to SIEM
            self.siem.send_block_event(threat.indicator, rule.rule_id)
            self.siem.send_alert(threat.indicator, reason, "blocked")
            
            logger.warning(f"BLOCKED: {threat.indicator} (Risk: {threat.risk_score})")
            return rule
        else:
            logger.error(f"Failed to add block rule for {threat.indicator}")
            return None
    
    def remove_block_rule(self, indicator: str, reason: str = "expired") -> bool:
        """Remove a block rule"""
        # Get the rule from database
        rule = self.db.db.blocking_rules.find_one({"indicator": indicator})
        if not rule:
            logger.warning(f"No rule found for {indicator}")
            return False
        
        # Remove from firewall
        success = False
        if self.firewall_type == "iptables":
            success = self._execute_iptables_command("remove", indicator)
        elif self.firewall_type == "nftables":
            success = self._execute_nftables_command("remove", indicator)
        
        if success:
            # Update database
            self.db.db.blocking_rules.update_one(
                {"indicator": indicator},
                {"$set": {"is_active": False}}
            )
            
            # Remove from Redis
            self.redis_client.delete(f"block:{indicator}")
            
            # Log audit
            audit = AuditLog(
                timestamp=datetime.utcnow(),
                action="block_removed",
                indicator=indicator,
                user_or_system="auto",
                details={"reason": reason}
            )
            self.db.log_audit(audit)
            
            logger.info(f"UNBLOCKED: {indicator} ({reason})")
            return True
        
        return False
    
    def monitor_high_risk_threats(self):
        """Monitor database for new high-risk threats and block them"""
        processed_keys = set()
        
        while self.running:
            try:
                # Get high-risk active threats
                high_risk_threats = self.db.get_high_risk_threats(
                    min_risk_score=self.high_risk_threshold
                )
                
                # Process new threats
                for threat in high_risk_threats:
                    cache_key = f"processed:{threat.indicator}"
                    
                    # Check if we've already processed this indicator
                    if not self.redis_client.exists(cache_key):
                        # Add block rule for high-risk threat
                        if threat.risk_score >= 90:
                            reason = f"critical_risk_{threat.risk_score}"
                        else:
                            reason = f"high_risk_{threat.risk_score}"
                        
                        rule = self.add_block_rule(threat, reason)
                        
                        # Mark as processed (don't reprocess for 24 hours)
                        self.redis_client.setex(cache_key, 86400, "1")
                
                # Sleep before next check
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in threat monitor: {e}")
                time.sleep(60)
    
    def cleanup_expired_rules(self):
        """Periodically clean up expired firewall rules"""
        while self.running:
            try:
                # Get expired rules from database
                expired_rules = self.db.db.blocking_rules.find({
                    "is_active": True,
                    "expires_at": {"$lt": datetime.utcnow()}
                })
                
                for rule_doc in expired_rules:
                    self.remove_block_rule(rule_doc['indicator'], "expired")
                
                # Also clean up old audit logs
                if datetime.utcnow().hour == 0:  # Once per day
                    self.db.cleanup_old_data()
                
                # Sleep for 1 hour between cleanup cycles
                time.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error in cleanup: {e}")
                time.sleep(300)
    
    def manual_block(self, indicator: str, reason: str, duration_seconds: int = None) -> bool:
        """Manually block an indicator (for SOC analysts)"""
        # Create a temporary threat object
        threat = ThreatIntel(
            indicator=indicator,
            threat_type=ThreatType.IP if self._is_ip(indicator) else ThreatType.DOMAIN,
            source_feeds=["manual"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            risk_score=100,  # Maximum risk for manual blocks
            severity=None,
            status=IntelStatus.ACTIVE,
            confidence=100,
            tags=["manual_block"]
        )
        
        # Override duration if specified
        if duration_seconds:
            original_duration = self.block_duration
            self.block_duration = duration_seconds
        
        rule = self.add_block_rule(threat, f"manual: {reason}")
        
        # Restore original duration
        if duration_seconds:
            self.block_duration = original_duration
        
        if rule:
            # Log with user info
            audit = AuditLog(
                timestamp=datetime.utcnow(),
                action="manual_block",
                indicator=indicator,
                user_or_system="soc_analyst",
                details={"reason": reason, "duration": duration_seconds or self.block_duration}
            )
            self.db.log_audit(audit)
            
        return rule is not None
    
    def manual_unblock(self, indicator: str, reason: str) -> bool:
        """Manually unblock an indicator"""
        success = self.remove_block_rule(indicator, f"manual: {reason}")
        
        if success:
            # Mark as false positive or whitelisted
            self.db.mark_as_false_positive(indicator, reason, "soc_analyst")
            
            audit = AuditLog(
                timestamp=datetime.utcnow(),
                action="manual_unblock",
                indicator=indicator,
                user_or_system="soc_analyst",
                details={"reason": reason}
            )
            self.db.log_audit(audit)
        
        return success
    
    def _is_ip(self, indicator: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ip_address(indicator)
            return True
        except ValueError:
            return False
    
    def get_active_blocks(self) -> List[Dict[str, Any]]:
        """Get list of currently active blocks"""
        active_rules = self.db.get_active_blocking_rules()
        return [
            {
                "indicator": rule.indicator,
                "expires_at": rule.expires_at.isoformat(),
                "reason": rule.reason,
                "risk_score": rule.risk_score,
                "hit_count": rule.hit_count
            }
            for rule in active_rules
        ]
    
    def start(self):
        """Start the policy enforcer"""
        self.running = True
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self.monitor_high_risk_threats,
            daemon=True
        )
        self.monitor_thread.start()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self.cleanup_expired_rules,
            daemon=True
        )
        self.cleanup_thread.start()
        
        logger.info("Dynamic Policy Enforcer started")
        logger.info(f"Firewall type: {self.firewall_type}")
        logger.info(f"Auto-block enabled: {self.auto_block_enabled}")
        logger.info(f"High-risk threshold: {self.high_risk_threshold}")
        logger.info(f"Block duration: {self.block_duration} seconds")
    
    def stop(self):
        """Stop the policy enforcer"""
        self.running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=10)
        
        logger.info("Dynamic Policy Enforcer stopped")