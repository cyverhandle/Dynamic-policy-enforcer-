# Advanced Threat Intelligence Platform (TIP) & Dynamic Policy Enforcer

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A production-ready Threat Intelligence Platform for financial institutions that automates OSINT collection, provides real-time threat detection, and dynamically enforces security policies across network infrastructure.

---

## 🎯 Executive Summary

Financial institutions face sophisticated cyber attacks including zero-day exploits and Advanced Persistent Threats (APTs). Traditional static defenses are insufficient against modern adversaries. This platform addresses that gap by providing:

- **Automated OSINT Collection** from 5+ threat intelligence feeds
- **Real-time Dynamic Policy Enforcement** with automatic firewall rule updates
- **SIEM Integration** via the ELK Stack for centralized monitoring
- **PCI-DSS Compliance** with immutable audit logging
- **Zero-touch Operations** — no human intervention required for common threats

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ADVANCED THREAT INTELLIGENCE PLATFORM                    |
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                       │
│  │ VirusTotal   │  │ AlienVault   │  │ Feodo Tracker│                       │
│  │ API          │  │ OTX API      │  │ Feed         │                       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                       │
│         │                 │                 │                               │
│         └─────────────────┼─────────────────┘                               │
│                           │                                                 │
│                    ┌──────▼───────┐                                         │
│                    │   Python     │                                         │
│                    │  Aggregator  │                                         │
│                    │  (Threaded)  │                                         │
│                    └──────┬───────┘                                         │
│                           │                                                 │
│                    ┌──────▼───────┐       ┌──────────────┐                  │
│                    │   MongoDB    │──────▶│    Redis     │                  |
│                    │  (Primary    │       │   (Cache)    │                  │
│                    │   Storage)   │       └──────────────┘                  │
│                    └──────┬───────┘                                         │
│                           │                                                 │
│         ┌─────────────────┼─────────────────┐                               │
│         │                 │                 │                               │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐                       │
│  │  ELK Stack   │  │   Policy     │  │    Alert     │                       │
│  │  (SIEM)      │  │  Enforcer    │  │   Manager    │                       │
│  │              │  │  (Daemon)    │  │              │                       │
│  └──────────────┘  └──────┬───────┘  └──────┬───────┘                       │
│                           │                 │                               │
│                    ┌──────▼───────┐  ┌──────▼───────┐                       │
│                    │  iptables    │  │  Slack /     │                       │
│                    │ (Netfilter)  │  │   Email      │                       │
│                    └──────────────┘  └──────────────┘                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

### 1. Threat Intelligence Collection
- **Multi-source OSINT aggregation** — VirusTotal, AlienVault OTX, Feodo Tracker, Tor Exit Nodes
- **Automatic deduplication** with fuzzy matching (85% similarity threshold)
- **Intelligent risk scoring** (0–100) based on 6 weighted factors
- **Normalization engine** for consistent indicator formatting across all sources

### 2. Dynamic Policy Enforcement
- **Zero-latency blocking** of high-risk indicators (risk score ≥ 70)
- **Configurable block durations** (default: 24 hours)
- **Support for `iptables` and `nftables`** on Linux systems
- **Redis-based cache** for sub-millisecond indicator lookup
- **Automatic rule expiration** and cleanup

### 3. SOC Analyst Interface
- **REST API** for manual analyst intervention
- **Kibana dashboard** with real-time threat visualizations
- **Rollback mechanism** to quickly unblock false positives
- **Comprehensive audit trail** for compliance reporting

### 4. SIEM Integration
- **Native ELK Stack integration** (Elasticsearch, Logstash, Kibana)
- **Structured JSON logging** for easy parsing and querying
- **Geolocation enrichment** for IP-based indicators
- **Historical threat analysis** and trend reporting

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Minimum |
|---|---|
| OS | Ubuntu 20.04+ / Debian 11+ |
| RAM | 8 GB |
| Storage | 50 GB |
| Python | 3.9+ |
| Other | Docker & Docker Compose |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/cyverhandle/Dynamic-policy-enforcer-.git
cd Dynamic-policy-enforcer-

# 2. Run the deployment script
chmod +x scripts/deploy.sh
sudo ./scripts/deploy.sh

# 3. Configure environment variables
cp .env.example .env
# Edit .env with your API keys (see Configuration section)

# 4. Start all services
docker-compose up -d

#5. Setup Environment
python -m venv tip_env
source tip_env/bin/activate
# 6. Initialize the database
python scripts/init_database.py

# 7. Start the platform
python src/main.py
```

### Verify Installation

```bash
# Check all services are running
docker-compose ps

# Test the API health endpoint
curl http://localhost:5001/api/health

# View the Kibana dashboard
open http://localhost:5601

# Check currently active blocks
curl http://localhost:5001/api/blocks
```

---

## 📡 API Reference

### `GET /api/blocks` — List Active Blocks

```json
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
```

### `POST /api/blocks` — Manually Block an Indicator

```http
POST /api/blocks
Content-Type: application/json

{
  "indicator": "45.227.254.8",
  "reason": "suspicious_activity",
  "duration_seconds": 3600
}
```

### `POST /api/rollback/{indicator}` — Remove a False Positive

```http
POST /api/rollback/185.130.5.253
Content-Type: application/json

{
  "reason": "false_positive_legitimate_service"
}
```

### `GET /api/stats` — Platform Statistics

```bash
curl http://localhost:5001/api/stats
```

---

## 📁 Project Structure

```
threat-intel-platform/
├── src/
│   ├── aggregators/          # OSINT feed collectors
│   │   ├── base_aggregator.py
│   │   ├── virustotal_aggregator.py
│   │   ├── alienvault_aggregator.py
│   │   ├── abuseibdb_aggregator.py
│   │   ├── feodo_aggregator.py
│   │   └── tor_aggregator.py
│   ├── database/             # MongoDB operations
│   │   ├── mongo_client.py
│   │   ├── models.py
│   │   └── deduplicator.py
│   ├── enforcer/             # Firewall management
│   │   ├── policy_enforcer.py
│   │   └── rollback_manager.py
│   ├── analytics/            # Risk scoring engine
│   │   └── risk_scorer.py
│   ├── api/                  # REST API server
│   │   └── app.py
│   ├── utils/                # Shared helpers
│   │   ├── logger.py
│   │   └── validators.py
│   └── main.py               # Application entry point
├── config/                   # Configuration files
├── scripts/                  # Setup and utility scripts
├── tests/                    # Unit and integration tests
├── docker-compose.yml        # Container orchestration
├── requirements.txt          # Python dependencies
└── README.md
```

---

## 🔒 Security

### PCI-DSS Compliance
- Immutable, append-only audit logs
- Configurable log retention (default: 1 year)
- Full user access logging for all operations
- Configuration change tracking

### Network Security
- Automatic threat blocking for indicators scoring ≥ 70
- Alert rate limiting (5-minute cooldown per indicator)
- Whitelist support to prevent repeated false positives
- TLS encryption for all API communication

### Operational Security
- API key authentication on all endpoints
- Input validation and sanitization for all indicators
- Session management
- Role-based access control *(planned)*

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage report
pytest --cov=src tests/

# Run a specific test file
pytest tests/test_integration.py

# Run performance benchmarks
python scripts/performance_test.py
```

---

## 📊 Monitoring & Alerting

### Kibana Dashboards
| Dashboard | Description |
|---|---|
| Threat Overview | Real-time threat statistics and counts |
| Geographic Distribution | World map of threat source locations |
| Risk Score Distribution | Histogram grouped by severity level |
| Block Rate Trends | Time-series analysis of blocking activity |

### Alert Channels
- **Slack** (default)
- **Email** (optional)
- **Webhook** (custom endpoints)

### Health Checks

```bash
# Overall system health
curl http://localhost:5001/api/health

# MongoDB connection status
curl http://localhost:5001/api/db/status

# Active firewall rules
iptables -L INPUT -n
```

---

## ⚙️ Configuration

### Environment Variables (`.env`)

```env
# Database
MONGODB_URI=mongodb://localhost:27017/
REDIS_HOST=localhost

# API Keys
VIRUSTOTAL_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here

# Policy Enforcement
FIREWALL_TYPE=iptables
BLOCK_DURATION_SECONDS=86400
HIGH_RISK_THRESHOLD=70
AUTO_BLOCK_ENABLED=true

# Alerting
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

### Risk Scoring Weights

```python
weights = {
    "feed_reputation":     0.20,  # Trustworthiness of the reporting source
    "age_factor":          0.15,  # How recently the indicator was observed
    "source_count":        0.15,  # Number of independent feeds reporting it
    "historical_activity": 0.20,  # Past block attempts for this indicator
    "indicator_type":      0.15,  # Type: IP, domain, hash, etc.
    "geo_risk":            0.15,  # Country-level risk rating
}
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
