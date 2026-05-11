#!/bin/bash
# =============================================================================
# Threat Intelligence Platform - Production Deployment Script
# Version: 1.0.0
# Author: Security Engineering Team
# Description: Complete deployment automation for TIP with all components
# =============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# =============================================================================
# COLOR CODES FOR OUTPUT
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/tip_deployment.log"
DEPLOYMENT_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/tip_backups/${DEPLOYMENT_TIMESTAMP}"

# Component versions
MONGODB_VERSION="6.0"
REDIS_VERSION="7-alpine"
ELASTICSEARCH_VERSION="8.11.0"
KIBANA_VERSION="8.11.0"
LOGSTASH_VERSION="8.11.0"

# Port configurations
MONGODB_PORT=27017
REDIS_PORT=6379
ELASTICSEARCH_PORT=9200
KIBANA_PORT=5601
LOGSTASH_PORT=5000
API_PORT=5001

# Resource limits
MONGODB_MEMORY="2G"
REDIS_MEMORY="1G"
ELASTICSEARCH_MEMORY="4G"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} - ${level} - ${message}" | tee -a "$LOG_FILE"
    
    case $level in
        "ERROR") echo -e "${RED}✗ ${message}${NC}" ;;
        "SUCCESS") echo -e "${GREEN}✓ ${message}${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠ ${message}${NC}" ;;
        "INFO") echo -e "${BLUE}ℹ ${message}${NC}" ;;
        "STEP") echo -e "\n${PURPLE}▶ ${message}${NC}" ;;
        *) echo -e "${message}" ;;
    esac
}

check_prerequisites() {
    log "STEP" "Checking system prerequisites..."
    
    # Check OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]] && [[ "$ID" != "debian" ]]; then
            log "WARNING" "Untested OS: $ID. Recommended: Ubuntu 20.04+ or Debian 11+"
        fi
    fi
    
    # Check root/sudo
    if [[ $EUID -eq 0 ]]; then
        log "WARNING" "Running as root. Sudo user recommended for security."
    elif ! sudo -n true 2>/dev/null; then
        log "ERROR" "Sudo privileges required. Please run with a user that has sudo access."
        exit 1
    fi
    
    # Check available memory
    local total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $total_mem -lt 8 ]]; then
        log "ERROR" "Insufficient memory: ${total_mem}GB. Minimum 8GB required."
        exit 1
    fi
    log "SUCCESS" "Memory check passed: ${total_mem}GB available"
    
    # Check available disk space
    local available_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ $available_space -lt 50 ]]; then
        log "ERROR" "Insufficient disk space: ${available_space}GB. Minimum 50GB required."
        exit 1
    fi
    log "SUCCESS" "Disk space check passed: ${available_space}GB available"
    
    # Check Python version
    if command -v python3 &>/dev/null; then
        python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if [[ $(echo "$python_version < 3.9" | bc) -eq 1 ]]; then
            log "ERROR" "Python 3.9+ required. Found: $python_version"
            exit 1
        fi
        log "SUCCESS" "Python version check passed: $python_version"
    else
        log "ERROR" "Python 3 not found"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &>/dev/null; then
        log "WARNING" "Docker not found. Will be installed."
    else
        docker_version=$(docker --version | awk '{print $3}' | sed 's/,//')
        log "SUCCESS" "Docker found: $docker_version"
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null; then
        log "WARNING" "Docker Compose not found. Will be installed."
    else
        log "SUCCESS" "Docker Compose found"
    fi
    
    log "SUCCESS" "All prerequisites satisfied"
}

# =============================================================================
# SYSTEM SETUP FUNCTIONS
# =============================================================================

setup_directories() {
    log "STEP" "Setting up directory structure..."
    
    # Create necessary directories
    sudo mkdir -p /opt/threat-intel-platform/{data,logs,config,backups,ssl,certs}
    sudo mkdir -p /data/{mongodb,redis,elasticsearch}
    sudo mkdir -p /var/log/tip/{aggregator,enforcer,api,siem}
    sudo mkdir -p /etc/tip/{policies,rules}
    
    # Set proper permissions
    sudo chown -R $USER:$USER /opt/threat-intel-platform
    sudo chmod 755 /opt/threat-intel-platform
    sudo chmod 700 /etc/tip  # Restricted access for policies
    
    # Create symlink for easy access
    sudo ln -sf /opt/threat-intel-platform /opt/tip
    
    log "SUCCESS" "Directory structure created"
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    log "INFO" "Backup directory created: $BACKUP_DIR"
}

install_system_dependencies() {
    log "STEP" "Installing system dependencies..."
    
    sudo apt-get update -qq
    
    # Essential packages
    local packages=(
        "apt-transport-https"
        "ca-certificates"
        "curl"
        "gnupg"
        "lsb-release"
        "software-properties-common"
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "build-essential"
        "libssl-dev"
        "libffi-dev"
        "git"
        "wget"
        "vim"
        "htop"
        "nethogs"
        "iftop"
        "iptables"
        "iptables-persistent"
        "netfilter-persistent"
        "ufw"
        "fail2ban"
        "logrotate"
        "jq"
        "unzip"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            sudo apt-get install -y "$package" >> "$LOG_FILE" 2>&1
            log "INFO" "Installed: $package"
        else
            log "INFO" "Already installed: $package"
        fi
    done
    
    log "SUCCESS" "System dependencies installed"
}

install_docker() {
    log "STEP" "Installing Docker and Docker Compose..."
    
    if ! command -v docker &>/dev/null; then
        # Install Docker
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        sudo sh /tmp/get-docker.sh >> "$LOG_FILE" 2>&1
        sudo usermod -aG docker $USER
        rm /tmp/get-docker.sh
        
        # Configure Docker daemon for better performance
        sudo mkdir -p /etc/docker
        cat <<EOF | sudo tee /etc/docker/daemon.json > /dev/null
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "exec-opts": ["native.cgroupdriver=systemd"],
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 65536
    }
  }
}
EOF
        
        sudo systemctl restart docker
        log "SUCCESS" "Docker installed successfully"
    else
        log "INFO" "Docker already installed"
    fi
    
    # Install Docker Compose
    if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null; then
        sudo curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        log "SUCCESS" "Docker Compose installed"
    else
        log "INFO" "Docker Compose already installed"
    fi
}

setup_firewall() {
    log "STEP" "Configuring firewall rules..."
    
    # Backup existing rules
    sudo iptables-save > "$BACKUP_DIR/iptables_backup.rules" 2>/dev/null || true
    
    # Create comprehensive iptables rules
    cat <<'EOF' | sudo tee /tmp/iptables_rules.sh > /dev/null
#!/bin/bash
# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Rate limiting for SSH (prevent brute force)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j DROP

# Allow MongoDB (internal only)
iptables -A INPUT -p tcp --dport 27017 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 27017 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 27017 -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -p tcp --dport 27017 -j DROP

# Allow Redis (internal only)
iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 6379 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 6379 -j DROP

# Allow Elasticsearch (internal only)
iptables -A INPUT -p tcp --dport 9200 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 9200 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 9200 -j DROP

# Allow Kibana (restricted)
iptables -A INPUT -p tcp --dport 5601 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 5601 -j DROP

# Allow API (restricted to internal network or VPN)
iptables -A INPUT -p tcp --dport 5001 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 5001 -j DROP

# Log dropped packets for monitoring
iptables -A INPUT -j LOG --log-prefix "IPTABLES-DROP: " --log-level 4
EOF
    
    sudo chmod +x /tmp/iptables_rules.sh
    sudo /tmp/iptables_rules.sh
    rm /tmp/iptables_rules.sh
    
    # Make rules persistent
    if command -v iptables-save &>/dev/null; then
        sudo netfilter-persistent save 2>/dev/null || sudo iptables-save > /etc/iptables/rules.v4
        log "SUCCESS" "Firewall rules applied and saved"
    else
        log "WARNING" "Could not save firewall rules persistently"
    fi
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

clone_repository() {
    log "STEP" "Setting up application code..."
    
    cd /opt/threat-intel-platform
    
    if [[ ! -d "src" ]]; then
        # Create basic directory structure
        mkdir -p src/{aggregators,database,enforcer,siem,api,alerting,analytics,utils,compliance}
        mkdir -p config scripts tests docs
        
        # Create virtual environment
        python3 -m venv venv
        source venv/bin/activate
        
        log "SUCCESS" "Application structure created"
    else
        log "INFO" "Application code already exists"
    fi
}

create_config_files() {
    log "STEP" "Creating configuration files..."
    
    cd /opt/threat-intel-platform
    
    # Create .env file
    if [[ ! -f ".env" ]]; then
        cat <<'EOF' > .env
# ============================================================================
# Threat Intelligence Platform - Environment Configuration
# ============================================================================

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=threat_intel
MONGODB_USER=tip_admin
MONGODB_PASSWORD=$(openssl rand -base64 32 2>/dev/null || echo "CHANGE_ME")

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=$(openssl rand -base64 32 2>/dev/null || echo "CHANGE_ME")

# API Keys (Required for threat feeds)
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_API_KEY_HERE
ALIENVAULT_API_KEY=YOUR_ALIENVAULT_API_KEY_HERE

# Optional Feeds (Can be left empty)
ABUSEIPDB_API_KEY=
IBM_XFORCE_API_KEY=

# Enforcement Configuration
FIREWALL_TYPE=iptables  # Options: iptables, nftables
BLOCK_DURATION_SECONDS=86400  # 24 hours
HIGH_RISK_THRESHOLD=70
AUTO_BLOCK_ENABLED=true

# Alert Configuration
SLACK_WEBHOOK_URL=
EMAIL_ENABLED=false
SMTP_SERVER=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
ALERT_RECIPIENTS=security@bank.com

# Compliance
AUDIT_RETENTION_DAYS=365
ENABLE_PCI_DSS_MODE=true

# Performance
COLLECTION_INTERVAL_SECONDS=1800
MAX_CONCURRENT_FEEDS=5
BATCH_SIZE=1000

# Logging
LOG_LEVEL=INFO
LOG_RETENTION_DAYS=30
EOF
        
        # Generate secure random passwords
        sed -i "s/MONGODB_PASSWORD=.*/MONGODB_PASSWORD=$(openssl rand -base64 32)/" .env
        sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$(openssl rand -base64 32)/" .env
        
        chmod 600 .env  # Restrict permissions
        log "SUCCESS" ".env file created with secure defaults"
        log "WARNING" "Please edit .env file to add your API keys!"
    else
        log "INFO" ".env file already exists"
    fi
    
    # Create docker-compose.yml
    cat <<'EOF' > docker-compose.yml
version: '3.8'

services:
  mongodb:
    image: mongo:${MONGODB_VERSION:-6.0}
    container_name: tip-mongodb
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGODB_USER:-admin}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGODB_PASSWORD}
      MONGO_INITDB_DATABASE: threat_intel
    ports:
      - "27017:27017"
    volumes:
      - /data/mongodb:/data/db
      - ./backups/mongodb:/backup
    networks:
      - tip-network
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.adminCommand('ping')"]
      interval: 30s
      timeout: 10s
      retries: 5

  redis:
    image: redis:${REDIS_VERSION:-7-alpine}
    container_name: tip-redis
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - /data/redis:/data
    networks:
      - tip-network
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:${ELASTICSEARCH_VERSION:-8.11.0}
    container_name: tip-elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
      - cluster.name=tip-cluster
      - node.name=tip-node-1
    ports:
      - "9200:9200"
    volumes:
      - /data/elasticsearch:/usr/share/elasticsearch/data
    networks:
      - tip-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9200/_cluster/health"]
      interval: 30s
      timeout: 10s
      retries: 5

  kibana:
    image: docker.elastic.co/kibana/kibana:${KIBANA_VERSION:-8.11.0}
    container_name: tip-kibana
    restart: unless-stopped
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - SERVER_NAME=kibana.tip.local
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - tip-network

networks:
  tip-network:
    driver: bridge
EOF
    
    log "SUCCESS" "Docker Compose configuration created"
}

create_requirements() {
    log "STEP" "Creating Python requirements file..."
    
    cat <<'EOF' > requirements.txt
# Core Dependencies
pymongo==4.5.0
redis==5.0.1
requests==2.31.0
beautifulsoup4==4.12.2
lxml==4.9.3

# API Framework
flask==3.0.0
flask-cors==4.0.0
flask-restx==1.2.0

# Data Processing
pandas==2.1.3
numpy==1.24.3
pydantic==2.5.0

# Threat Intelligence
virustotal-python==1.0.2
otx-python-sdk==1.5.8

# SIEM Integration
elasticsearch==8.11.0
python-logstash==0.4.8

# Security & Crypto
cryptography==41.0.7
bcrypt==4.1.2
python-jose==3.3.0

# Monitoring & Metrics
prometheus-client==0.19.0
psutil==5.9.6

# Utilities
python-dotenv==1.0.0
pyyaml==6.0.1
click==8.1.7
schedule==1.2.0
colorlog==6.8.0

# Testing
pytest==7.4.3
pytest-cov==4.1.0
pytest-mock==3.12.0
EOF
    
    log "SUCCESS" "Requirements file created"
}

setup_python_environment() {
    log "STEP" "Setting up Python virtual environment..."
    
    cd /opt/threat-intel-platform
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log "INFO" "Virtual environment created"
    fi
    
    # Activate and install packages
    source venv/bin/activate
    pip install --upgrade pip setuptools wheel >> "$LOG_FILE" 2>&1
    pip install -r requirements.txt >> "$LOG_FILE" 2>&1
    
    log "SUCCESS" "Python dependencies installed"
}

# =============================================================================
# COMPONENT STARTUP FUNCTIONS
# =============================================================================

start_docker_services() {
    log "STEP" "Starting Docker services..."
    
    cd /opt/threat-intel-platform
    
    # Pull latest images
    docker-compose pull >> "$LOG_FILE" 2>&1
    
    # Start services
    docker-compose up -d >> "$LOG_FILE" 2>&1
    
    # Wait for services to be healthy
    log "INFO" "Waiting for services to become healthy..."
    sleep 30
    
    # Check service status
    docker-compose ps
    
    log "SUCCESS" "Docker services started"
}

initialize_database() {
    log "STEP" "Initializing database..."
    
    # Source environment variables
    source /opt/threat-intel-platform/.env
    
    # Wait for MongoDB to be ready
    until mongosh --host localhost --port 27017 --eval "db.runCommand({ping: 1})" &>/dev/null; do
        log "INFO" "Waiting for MongoDB..."
        sleep 5
    done
    
    # Create database and collections
    cat <<EOF | mongosh --host localhost --port 27017 >> "$LOG_FILE" 2>&1
use threat_intel

// Create collections
db.createCollection("threat_intel")
db.createCollection("blocking_rules")
db.createCollection("audit_logs")
db.createCollection("whitelist")
db.createCollection("alerts")
db.createCollection("system_health")

// Create indexes for threat_intel
db.threat_intel.createIndex({ "indicator": 1 }, { unique: true })
db.threat_intel.createIndex({ "risk_score": -1 })
db.threat_intel.createIndex({ "last_seen": -1 })
db.threat_intel.createIndex({ "status": 1 })
db.threat_intel.createIndex({ "severity": 1 })
db.threat_intel.createIndex({ "tags": 1 })
db.threat_intel.createIndex({ "indicator": "text" })

// Create indexes for blocking_rules
db.blocking_rules.createIndex({ "indicator": 1 }, { unique: true })
db.blocking_rules.createIndex({ "expires_at": 1 })
db.blocking_rules.createIndex({ "is_active": 1 })
db.blocking_rules.createIndex({ "created_at": -1 })

// Create indexes for audit_logs
db.audit_logs.createIndex({ "timestamp": -1 })
db.audit_logs.createIndex({ "action": 1 })
db.audit_logs.createIndex({ "user_or_system": 1 })
db.audit_logs.createIndex({ "timestamp": 1, "action": 1 })

// Create capped collection for high-frequency audit (append-only)
db.createCollection("audit_logs_recent", { capped: true, size: 104857600 }) // 100MB

// Create indexes for whitelist
db.whitelist.createIndex({ "indicator": 1 }, { unique: true })
db.whitelist.createIndex({ "added_at": -1 })

// Create indexes for alerts
db.alerts.createIndex({ "timestamp": -1 })
db.alerts.createIndex({ "severity": 1 })
db.alerts.createIndex({ "status": 1 })

print("Database initialization complete!")
EOF
    
    log "SUCCESS" "Database initialized"
}

configure_kibana() {
    log "STEP" "Configuring Kibana dashboards..."
    
    # Wait for Kibana to be ready
    until curl -s "http://localhost:5601/api/status" | grep -q '"level":"available"'; do
        log "INFO" "Waiting for Kibana to be ready..."
        sleep 10
    done
    
    # Create index pattern
    curl -X POST "http://localhost:5601/api/saved_objects/index-pattern/threat-intel-*" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
            "attributes": {
                "title": "threat-intel-*",
                "timeFieldName": "@timestamp"
            }
        }' >> "$LOG_FILE" 2>&1 || log "WARNING" "Could not create index pattern automatically"
    
    log "SUCCESS" "Kibana configured"
}

# =============================================================================
# APPLICATION STARTUP FUNCTIONS
# =============================================================================

create_systemd_services() {
    log "STEP" "Creating systemd service files..."
    
    # Main orchestrator service
    cat <<'EOF' | sudo tee /etc/systemd/system/tip-orchestrator.service > /dev/null
[Unit]
Description=Threat Intelligence Platform Orchestrator
After=network.target mongodb.service redis.service
Wants=mongodb.service redis.service

[Service]
Type=simple
User=tip
Group=tip
WorkingDirectory=/opt/threat-intel-platform
Environment="PATH=/opt/threat-intel-platform/venv/bin"
EnvironmentFile=/opt/threat-intel-platform/.env
ExecStart=/opt/threat-intel-platform/venv/bin/python /opt/threat-intel-platform/src/main.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tip-orchestrator

[Install]
WantedBy=multi-user.target
EOF

    # Policy enforcer service
    cat <<'EOF' | sudo tee /etc/systemd/system/tip-enforcer.service > /dev/null
[Unit]
Description=Threat Intelligence Platform Policy Enforcer
After=network.target tip-orchestrator.service
Requires=tip-orchestrator.service

[Service]
Type=simple
User=tip
Group=tip
WorkingDirectory=/opt/threat-intel-platform
Environment="PATH=/opt/threat-intel-platform/venv/bin"
EnvironmentFile=/opt/threat-intel-platform/.env
ExecStart=/opt/threat-intel-platform/venv/bin/python /opt/threat-intel-platform/src/enforcer/policy_enforcer.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tip-enforcer

[Install]
WantedBy=multi-user.target
EOF

    # API service
    cat <<'EOF' | sudo tee /etc/systemd/system/tip-api.service > /dev/null
[Unit]
Description=Threat Intelligence Platform REST API
After=network.target tip-orchestrator.service

[Service]
Type=simple
User=tip
Group=tip
WorkingDirectory=/opt/threat-intel-platform
Environment="PATH=/opt/threat-intel-platform/venv/bin"
EnvironmentFile=/opt/threat-intel-platform/.env
ExecStart=/opt/threat-intel-platform/venv/bin/python /opt/threat-intel-platform/src/api/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tip-api

[Install]
WantedBy=multi-user.target
EOF

    # Create tip user if not exists
    if ! id "tip" &>/dev/null; then
        sudo useradd -r -s /bin/bash -m -d /home/tip tip
        sudo usermod -aG docker tip
    fi
    
    # Set proper permissions
    sudo chown -R tip:tip /opt/threat-intel-platform
    sudo chmod 755 /etc/systemd/system/tip-*.service
    
    # Reload systemd
    sudo systemctl daemon-reload
    
    log "SUCCESS" "Systemd services created"
}

start_services() {
    log "STEP" "Starting Threat Intelligence Platform services..."
    
    # Enable services to start on boot
    sudo systemctl enable tip-orchestrator.service
    sudo systemctl enable tip-enforcer.service
    sudo systemctl enable tip-api.service
    
    # Start services
    sudo systemctl start tip-orchestrator.service
    sleep 5
    sudo systemctl start tip-enforcer.service
    sleep 5
    sudo systemctl start tip-api.service
    
    # Check service status
    echo ""
    sudo systemctl status tip-orchestrator.service --no-pager
    echo ""
    sudo systemctl status tip-enforcer.service --no-pager
    echo ""
    sudo systemctl status tip-api.service --no-pager
    
    log "SUCCESS" "All services started"
}

# =============================================================================
# MONITORING AND LOGGING SETUP
# =============================================================================

setup_monitoring() {
    log "STEP" "Setting up monitoring and logging..."
    
    # Configure log rotation
    cat <<'EOF' | sudo tee /etc/logrotate.d/tip > /dev/null
/var/log/tip/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 tip tip
    sharedscripts
    postrotate
        systemctl reload tip-orchestrator > /dev/null 2>&1 || true
    endscript
}
EOF
    
    # Configure fail2ban for API
    cat <<'EOF' | sudo tee /etc/fail2ban/jail.d/tip-api.local > /dev/null
[tip-api]
enabled = true
port = 5001
filter = tip-api
logpath = /var/log/tip/api.log
maxretry = 5
bantime = 3600
findtime = 600
EOF
    
    # Create fail2ban filter
    cat <<'EOF' | sudo tee /etc/fail2ban/filter.d/tip-api.conf > /dev/null
[Definition]
failregex = ^.*Failed login attempt from <HOST>.*$
ignoreregex =
EOF
    
    sudo systemctl restart fail2ban 2>/dev/null || true
    
    log "SUCCESS" "Monitoring and logging configured"
}

setup_backup_cron() {
    log "STEP" "Setting up automated backups..."
    
    # Create backup script
    cat <<'EOF' | sudo tee /usr/local/bin/tip-backup.sh > /dev/null
#!/bin/bash
BACKUP_DIR="/opt/tip_backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

# Backup MongoDB
mongodump --out $BACKUP_DIR/mongodb

# Backup configuration
cp -r /opt/threat-intel-platform/config $BACKUP_DIR/
cp /opt/threat-intel-platform/.env $BACKUP_DIR/

# Backup firewall rules
iptables-save > $BACKUP_DIR/iptables.rules

# Compress backup
tar -czf $BACKUP_DIR.tar.gz $BACKUP_DIR/
rm -rf $BACKUP_DIR

# Keep only last 30 days of backups
find /opt/tip_backups -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR.tar.gz"
EOF
    
    sudo chmod +x /usr/local/bin/tip-backup.sh
    
    # Add to crontab (daily at 2 AM)
    (sudo crontab -l 2>/dev/null | grep -v "tip-backup.sh"; echo "0 2 * * * /usr/local/bin/tip-backup.sh >> /var/log/tip_backup.log 2>&1") | sudo crontab -
    
    log "SUCCESS" "Automated backup configured (daily at 2 AM)"
}

# =============================================================================
# VALIDATION AND HEALTH CHECK
# =============================================================================

validate_deployment() {
    log "STEP" "Validating deployment..."
    
    local all_healthy=true
    
    # Check MongoDB
    if mongosh --eval "db.runCommand({ping: 1})" &>/dev/null; then
        log "SUCCESS" "MongoDB is healthy"
    else
        log "ERROR" "MongoDB is not responding"
        all_healthy=false
    fi
    
    # Check Redis
    if redis-cli ping &>/dev/null; then
        log "SUCCESS" "Redis is healthy"
    else
        log "ERROR" "Redis is not responding"
        all_healthy=false
    fi
    
    # Check Elasticsearch
    if curl -s "http://localhost:9200/_cluster/health" | grep -q '"status":"\(green\|yellow\)"'; then
        log "SUCCESS" "Elasticsearch is healthy"
    else
        log "ERROR" "Elasticsearch is not healthy"
        all_healthy=false
    fi
    
    # Check API
    if curl -s "http://localhost:5001/api/health" | grep -q "operational"; then
        log "SUCCESS" "API is healthy"
    else
        log "ERROR" "API is not responding"
        all_healthy=false
    fi
    
    # Check firewall rules
    if iptables -L INPUT -n | grep -q "DROP"; then
        log "SUCCESS" "Firewall rules are active"
    else
        log "WARNING" "Firewall rules may not be properly configured"
    fi
    
    if $all_healthy; then
        log "SUCCESS" "All components are healthy!"
        return 0
    else
        log "ERROR" "Some components are not healthy. Please check logs."
        return 1
    fi
}

# =============================================================================
# DEPLOYMENT SUMMARY
# =============================================================================

print_summary() {
    echo ""
    echo "================================================================================"
    echo -e "${GREEN}🎉 Threat Intelligence Platform Deployment Complete!${NC}"
    echo "================================================================================"
    echo ""
    echo -e "${CYAN}📊 Access Points:${NC}"
    echo "  • Kibana Dashboard:     http://localhost:5601"
    echo "  • REST API:             http://localhost:5001"
    echo "  • MongoDB:              localhost:27017"
    echo "  • Redis:                localhost:6379"
    echo "  • Elasticsearch:        localhost:9200"
    echo ""
    echo -e "${CYAN}🔧 Management Commands:${NC}"
    echo "  • View orchestrator logs:   sudo journalctl -u tip-orchestrator -f"
    echo "  • View enforcer logs:       sudo journalctl -u tip-enforcer -f"
    echo "  • View API logs:            sudo journalctl -u tip-api -f"
    echo "  • Restart all services:     sudo systemctl restart tip-{orchestrator,enforcer,api}"
    echo "  • Check service status:     sudo systemctl status tip-{orchestrator,enforcer,api}"
    echo ""
    echo -e "${CYAN}📁 Important Paths:${NC}"
    echo "  • Application:          /opt/threat-intel-platform"
    echo "  • Configuration:        /opt/threat-intel-platform/.env"
    echo "  • Logs:                 /var/log/tip/"
    echo "  • Backups:              /opt/tip_backups/"
    echo "  • Database:             /data/mongodb"
    echo ""
    echo -e "${CYAN}🔐 Security Notes:${NC}"
    echo "  • API keys stored in:   /opt/threat-intel-platform/.env"
    echo "  • Firewall rules applied and persisted"
    echo "  • Audit logging enabled"
    echo "  • Daily backups configured at 2 AM"
    echo ""
    echo -e "${YELLOW}⚠️  Next Steps:${NC}"
    echo "  1. Edit /opt/threat-intel-platform/.env to add your API keys"
    echo "  2. Configure Slack webhook URL for alerts"
    echo "  3. Review firewall rules in /etc/iptables/rules.v4"
    echo "  4. Access Kibana at http://localhost:5601 to create dashboards"
    echo "  5. Test the API: curl http://localhost:5001/api/health"
    echo ""
    echo -e "${GREEN}Deployment log saved to: $LOG_FILE${NC}"
    echo "================================================================================"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    echo ""
    echo "================================================================================"
    echo -e "${GREEN}Threat Intelligence Platform - Production Deployment${NC}"
    echo "================================================================================"
    echo ""
    
    # Create log directory
    sudo mkdir -p $(dirname "$LOG_FILE")
    sudo chown $USER:$USER $(dirname "$LOG_FILE")
    
    log "INFO" "Starting deployment at $DEPLOYMENT_TIMESTAMP"
    log "INFO" "Log file: $LOG_FILE"
    
    # Execute deployment steps
    check_prerequisites
    setup_directories
    install_system_dependencies
    install_docker
    setup_firewall
    clone_repository
    create_config_files
    create_requirements
    setup_python_environment
    start_docker_services
    initialize_database
    configure_kibana
    create_systemd_services
    start_services
    setup_monitoring
    setup_backup_cron
    
    # Validate deployment
    if validate_deployment; then
        print_summary
        log "SUCCESS" "Deployment completed successfully!"
        exit 0
    else
        log "ERROR" "Deployment completed with issues. Please check the logs."
        exit 1
    fi
}

# Run main function
main "$@"
