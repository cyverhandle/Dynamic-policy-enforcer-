# Advanced Threat Intelligence Platform (TIP) & Dynamic Policy Enforcer

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A production-ready Threat Intelligence Platform for financial institutions that automates OSINT collection, provides real-time threat detection, and dynamically enforces security policies across network infrastructure.

## 🎯 Executive Summary

Financial institutions face sophisticated cyber attacks including zero-day exploits and APTs. Traditional static defenses are insufficient. This platform provides:

- **Automated OSINT Collection** from 5+ threat feeds
- **Real-time Dynamic Policy Enforcement** with automatic firewall updates
- **SIEM Integration** (ELK Stack) for centralized monitoring
- **Compliance Ready** with PCI-DSS audit logging
- **Zero-touch Operations** - no human intervention required for common threats

## 🏗️ Architecture Overview
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ADVANCED THREAT INTELLIGENCE PLATFORM                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                      │
│  │ VirusTotal   │  │ AlienVault   │  │ Feodo Tracker│                      │
│  │ API          │  │ OTX API      │  │ Feed         │                      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                      │
│         │                 │                 │                               │
│         └─────────────────┼─────────────────┘                               │
│                           │                                                 │
│                    ┌──────▼───────┐                                         │
│                    │  Python      │                                         │
│                    │  Aggregator  │                                         │
│                    │  (Threaded)  │                                         │
│                    └──────┬───────┘                                         │
│                           │                                                 │
│                    ┌──────▼───────┐       ┌──────────────┐                 │
│                    │   MongoDB    │──────▶│   Redis      │                 │
│                    │  (Primary    │       │  (Cache)     │                 │
│                    │   Storage)   │       └──────────────┘                 │
│                    └──────┬───────┘                                         │
│                           │                                                 │
│         ┌─────────────────┼─────────────────┐                              │
│         │                 │                 │                              │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐                      │
│  │  ELK Stack   │  │  Policy      │  │  Alert      │                      │
│  │  (SIEM)      │  │  Enforcer    │  │  Manager    │                      │
│  │              │  │  (Daemon)    │  │             │                      │
│  └──────────────┘  └──────┬───────┘  └──────┬───────┘                      │
│                           │                 │                               │
│                    ┌──────▼───────┐  ┌──────▼───────┐                      │
│                    │  iptables    │  │  Slack/     │                      │
│                    │  (Netfilter) │  │  Email      │                      │
│                    └──────────────┘  └─────────────┘                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
## ✨ Key Features

### 1. Threat Intelligence Collection
- **Multi-source OSINT aggregation** (VirusTotal, AlienVault OTX, Feodo Tracker, Tor Exit Nodes)
- **Automatic deduplication** with fuzzy matching (85% similarity threshold)
- **Intelligent risk scoring** (0-100) based on 6 factors
- **Normalization engine** for consistent indicator formatting

### 2. Dynamic Policy Enforcement
- **Zero-latency blocking** of high-risk indicators (≥70 risk score)
- **Configurable block durations** (default 24 hours)
- **Support for iptables and nftables** on Linux
- **Redis-based cache** for sub-millisecond lookup
- **Automatic rule expiration** and cleanup

### 3. SOC Analyst Interface
- **REST API** for manual intervention
- **Kibana dashboard** with real-time visualizations
- **Rollback mechanism** for false positives
- **Comprehensive audit trail** for compliance

### 4. SIEM Integration
- **Native ELK Stack integration** (Elasticsearch, Logstash, Kibana)
- **Structured JSON logging** for easy parsing
- **Geolocation enrichment** for IP addresses
- **Historical threat analysis**

## 🚀 Quick Start

### Prerequisites

```bash
# System Requirements
- Ubuntu 20.04+ / Debian 11+
- 8GB RAM minimum
- 50GB storage
- Python 3.9+
- Docker & Docker Compose
```
Installation 
# 1. Clone the repository
git clone https://github.com/your-org/threat-intel-platform.git
cd threat-intel-platform

# 2. Run deployment script
chmod +x scripts/deploy.sh
sudo ./scripts/deploy.sh

# 3. Configure environment variables
cp .env.example .env
# Edit .env with your API keys

# 4. Start all services
docker-compose up -d

# 5. Initialize database
python scripts/init_database.py

# 6. Start the platform
python src/main.py

Verify Installation 
# Check services
docker-compose ps

# Test API
curl http://localhost:5001/api/health

# View Kibana dashboard
open http://localhost:5601

# Check active blocks
curl http://localhost:5001/api/blocks

📊 API Reference
GET /api/blocks
Response:
{
  "count": 42,
  "blocks": [
    {
      "indicator": "185.130.5.253",
      "expires_at": "2024-01-15T10:30:00Z",
      "reason": "high_risk_95",
      "hit_count": 3
    }
  ]
}



# Manual Block
POST /api/blocks
Content-Type: application/json

{
  "indicator": "45.227.254.8",
  "reason": "suspicious_activity",
  "duration_seconds": 3600
}

# Rollback False Positive
POST /api/rollback/185.130.5.253
Content-Type: application/json

{
  "reason": "false_positive_legitimate_service"
}
# Get Statistics
GET /api/stats

# 📁 Project Structure

threat-intel-platform/
├── src/
│   ├── aggregators/          # OSINT feed collectors
│   │   ├── base_aggregator.py
│   │   ├── virustotal_aggregator.py
│   │   ├── alienvault_aggregator.py
│   │   ├── feodo_aggregator.py
│   │   └── tor_aggregator.py
│   ├── database/             # MongoDB operations
│   │   ├── mongo_client.py
│   │   ├── models.py
│   │   └── deduplicator.py
│   ├── enforcer/             # Firewall management
│   │   ├── policy_enforcer.py
│   │   └── rollback_manager.py
│   ├── analytics/            # Risk scoring
│   │   └── risk_scorer.py
│   ├── api/                  # REST API
│   │   └── app.py
│   ├── utils/                # Helpers
│   │   ├── logger.py
│   │   └── validators.py
│   └── main.py               # Application entry point
├── config/                   # Configuration files
├── scripts/                  # Setup scripts
├── tests/                    # Unit tests
├── docker-compose.yml        # Container orchestration
├── requirements.txt          # Python dependencies
└── README.md                 # This file


# 🔒 Security Features
# PCI-DSS Compliance
Immutable audit logs (append-only)

1-year log retention (configurable)

User access logging for all operations

Configuration change tracking

# Network Security
Automatic threat blocking (70+ risk score)

Rate limiting for alerts (5 min cooldown)

Whitelist support for false positives

Encrypted API communication (TLS)

# Operational Security
Role-based access control (planned)

API key authentication

Session management

Input validation (all indicators sanitized)


# Testings 
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Run specific test
pytest tests/test_integration.py

# Performance test
python scripts/performance_test.py

📊 Monitoring & Alerting
Kibana Dashboards
Threat Overview: Real-time threat statistics

Geographic Distribution: Map of threat sources

Risk Score Distribution: Histogram by severity

Block Rate Trends: Time-series analysis

# Alert Channels
Slack (default)

Email (optional)

Webhook (custom endpoints)

# Health Checks
# System health
curl http://localhost:5001/api/health

# MongoDB status
curl http://localhost:5001/api/db/status

# Firewall status
iptables -L INPUT -n


# 🔧 Configuration

Environment Variables (.env)
# Database
MONGODB_URI=mongodb://localhost:27017/
REDIS_HOST=localhost

# Security
VIRUSTOTAL_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here

# Enforcement
FIREWALL_TYPE=iptables
BLOCK_DURATION_SECONDS=86400
HIGH_RISK_THRESHOLD=70
AUTO_BLOCK_ENABLED=true

# Alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/...


# Risk Scoring Weights
weights = {
    "feed_reputation": 0.20,    # Trustworthiness of source
    "age_factor": 0.15,         # How recently seen
    "source_count": 0.15,       # Number of feeds reporting
    "historical_activity": 0.20,# Past block attempts
    "indicator_type": 0.15,     # IP, domain, hash, etc.
    "geo_risk": 0.15            # Country risk level
}


