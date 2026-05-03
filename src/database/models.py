from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum

class ThreatType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CIDR = "cidr"

class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IntelStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"
    INVESTIGATING = "investigating"

@dataclass
class ThreatIntel:
    """Main threat intelligence data model"""
    indicator: str
    threat_type: ThreatType
    source_feeds: List[str]
    first_seen: datetime
    last_seen: datetime
    risk_score: int  # 0-100
    severity: ThreatSeverity
    status: IntelStatus
    confidence: int  # 0-100
    tags: List[str]
    geo_location: Optional[Dict[str, Any]] = None
    related_indicators: List[str] = None
    comments: List[Dict[str, Any]] = None
    block_count: int = 0
    last_blocked_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.related_indicators is None:
            self.related_indicators = []
        if self.comments is None:
            self.comments = []
        self._calculate_severity()
    
    def _calculate_severity(self):
        """Calculate severity based on risk score"""
        if self.risk_score >= 90:
            self.severity = ThreatSeverity.CRITICAL
        elif self.risk_score >= 70:
            self.severity = ThreatSeverity.HIGH
        elif self.risk_score >= 40:
            self.severity = ThreatSeverity.MEDIUM
        else:
            self.severity = ThreatSeverity.LOW
    
    def to_mongo(self) -> Dict[str, Any]:
        """Convert to MongoDB document"""
        doc = asdict(self)
        doc['threat_type'] = self.threat_type.value
        doc['severity'] = self.severity.value
        doc['status'] = self.status.value
        return doc
    
    @classmethod
    def from_mongo(cls, data: Dict[str, Any]) -> 'ThreatIntel':
        """Create from MongoDB document"""
        data['threat_type'] = ThreatType(data['threat_type'])
        data['severity'] = ThreatSeverity(data['severity'])
        data['status'] = IntelStatus(data['status'])
        return cls(**data)

@dataclass
class BlockingRule:
    """Firewall blocking rule model"""
    rule_id: str
    indicator: str
    threat_type: ThreatType
    created_at: datetime
    expires_at: datetime
    created_by: str  # 'auto' or 'manual'
    reason: str
    risk_score: int
    is_active: bool = True
    hit_count: int = 0
    last_hit_at: Optional[datetime] = None
    
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
    
    def to_mongo(self) -> Dict[str, Any]:
        doc = asdict(self)
        doc['threat_type'] = self.threat_type.value
        return doc

@dataclass
class AuditLog:
    """Audit log for compliance"""
    timestamp: datetime
    action: str  # 'block_added', 'block_removed', 'rule_modified', 'false_positive'
    indicator: str
    user_or_system: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    
    def to_mongo(self) -> Dict[str, Any]:
        return asdict(self)
