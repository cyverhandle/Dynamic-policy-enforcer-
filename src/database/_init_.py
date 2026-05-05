"""
Database Module for Threat Intelligence Platform
Handles MongoDB connections, data models, and deduplication
"""

from src.database.mongo_client import MongoDBClient
from src.database.models import (
    ThreatIntel,
    ThreatType,
    ThreatSeverity,
    IntelStatus,
    BlockingRule,
    AuditLog
)
from src.database.deduplicator import ThreatDeduplicator

__all__ = [
    "MongoDBClient",
    "ThreatIntel",
    "ThreatType",
    "ThreatSeverity",
    "IntelStatus",
    "BlockingRule",
    "AuditLog",
    "ThreatDeduplicator"
]
