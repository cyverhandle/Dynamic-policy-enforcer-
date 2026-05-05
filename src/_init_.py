"""
Threat Intelligence Platform - Advanced Threat Intelligence Platform & Dynamic Policy Enforcer
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__description__ = "Advanced Threat Intelligence Platform for Financial Institutions"

from src.database.mongo_client import MongoDBClient
from src.database.models import ThreatIntel, ThreatType, ThreatSeverity, IntelStatus, BlockingRule, AuditLog
from src.enforcer.policy_enforcer import FirewallEnforcer
from src.aggregators.base_aggregator import BaseAggregator

__all__ = [
    "MongoDBClient",
    "ThreatIntel",
    "ThreatType",
    "ThreatSeverity",
    "IntelStatus",
    "BlockingRule",
    "AuditLog",
    "FirewallEnforcer",
    "BaseAggregator"
]
