import os
from dataclasses import dataclass, field
from typing import List, Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

@dataclass
class DatabaseConfig:
    mongodb_uri: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
    mongodb_db: str = os.getenv("MONGODB_DB", "threat_intel")
    redis_host: str = os.getenv("REDIS_HOST", "localhost")
    redis_port: int = int(os.getenv("REDIS_PORT", 6379))
    redis_db: int = int(os.getenv("REDIS_DB", 0))

@dataclass
class APIConfig:
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    alienvault_api_key: str = os.getenv("ALIENVAULT_API_KEY", "")
    
@dataclass
class EnforcementConfig:
    firewall_type: str = os.getenv("FIREWALL_TYPE", "iptables")
    block_duration_seconds: int = int(os.getenv("BLOCK_DURATION", 86400))
    high_risk_threshold: int = int(os.getenv("HIGH_RISK_THRESHOLD", 70))
    auto_block_enabled: bool = os.getenv("AUTO_BLOCK_ENABLED", "True").lower() == "true"

@dataclass
class AlertConfig:
    slack_webhook_url: str = os.getenv("SLACK_WEBHOOK_URL", "")
    email_enabled: bool = os.getenv("EMAIL_ENABLED", "False").lower() == "true"
    smtp_server: str = os.getenv("SMTP_SERVER", "")
    # Fix: Use default_factory for mutable default
    alert_recipients: List[str] = field(default_factory=list)

class Config:
    def __init__(self):
        self.database = DatabaseConfig()
        self.api = APIConfig()
        self.enforcement = EnforcementConfig()
        self.alert = AlertConfig()
    
    @property
    def threat_feeds(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "virustotal",
                "enabled": bool(self.api.virustotal_api_key),
                "interval_seconds": 3600,
                "risk_score_base": 85
            },
            {
                "name": "alienvault",
                "enabled": bool(self.api.alienvault_api_key),
                "interval_seconds": 1800,
                "risk_score_base": 75
            },
            {
                "name": "feodo_tracker",
                "enabled": True,
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "interval_seconds": 3600,
                "risk_score_base": 90
            },
            {
                "name": "tor_exit_nodes",
                "enabled": True,
                "url": "https://check.torproject.org/torbulkexitlist",
                "interval_seconds": 7200,
                "risk_score_base": 60
            }
        ]

# Create global config instance
config = Config()
