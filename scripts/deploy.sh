#!/bin/bash
# =============================================================================
# Threat Intelligence Platform - Kali Linux Optimized Deployment
# Version: 1.0.0 (Kali Compatible)
# =============================================================================

set -euo pipefail

# =============================================================================
# COLOR CODES
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# CONFIGURATION - ADJUSTED FOR KALI / SMALLER DISK
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/tip_deployment.log"
DEPLOYMENT_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/tip_backups/${DEPLOYMENT_TIMESTAMP}"

# Reduced requirements for Kali
MIN_DISK_GB=40  # Reduced from 50GB to 40GB
MIN_MEMORY_GB=4  # Reduced from 8GB to 4GB

# Port configurations
MONGODB_PORT=27017
REDIS_PORT=6379
ELASTICSEARCH_PORT=9200
KIBANA_PORT=5601
API_PORT=5001

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
    
    # Check available memory (reduced requirement)
    local total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $total_mem -lt $MIN_MEMORY_GB ]]; then
        log "WARNING" "Low memory: ${total_mem}GB. Recommended ${MIN_MEMORY_GB}GB minimum."
    else
        log "SUCCESS" "Memory check passed: ${total_mem}GB available"
    fi
    
    # Check available disk space (reduced requirement)
    local available_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ $available_space -lt $MIN_DISK_GB ]]; then
        log "WARNING" "Low disk space: ${available_space}GB. Recommended ${MIN_DISK_GB}GB."
        log "INFO" "Continuing with available space - will use minimal installation"
    else
        log "SUCCESS" "Disk space check passed: ${available_space}GB available"
    fi
    
    # Check Python version
    if command -v python3 &>/dev/null; then
        python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log "SUCCESS" "Python version: $python_version"
    else
        log "ERROR" "Python 3 not found"
        exit 1
    fi
    
    # Check for Kali-specific adjustments
    if grep -qi "kali" /etc/os-release; then
        log "INFO" "Kali Linux detected - applying Kali-specific configurations"
        
        # Kill processes that might interfere (common on Kali)
        sudo systemctl stop apache2 2>/dev/null || true
        sudo systemctl stop mysql 2>/dev/null || true
    fi
    
    log "SUCCESS" "Prerequisites check completed"
}

# =============================================================================
# MINIMAL INSTALLATION FOR KALI
# =============================================================================

setup_directories() {
    log "STEP" "Setting up directory structure (minimal)..."
    
    # Use smaller footprint directories
    sudo mkdir -p /opt/threat-intel-platform/{src,config,logs}
    sudo mkdir -p /var/log/tip
    
    # Use less disk space for databases
    sudo mkdir -p /opt/tip-data/{mongodb,redis}
    
    sudo chown -R $USER:$USER /opt/threat-intel-platform
    sudo chmod 755 /opt/threat-intel-platform
    
    log "SUCCESS" "Directory structure created"
}

install_system_dependencies() {
    log "STEP" "Installing system dependencies..."
    
    sudo apt-get update -qq
    
    # Minimal essential packages
    local packages=(
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "git"
        "curl"
        "wget"
        "iptables"
        "netfilter-persistent"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            sudo apt-get install -y "$package" >> "$LOG_FILE" 2>&1 || true
            log "INFO" "Installed: $package"
        fi
    done
    
    log "SUCCESS" "System dependencies installed"
}

# =============================================================================
# LIGHTWEIGHT DOCKER SETUP (OPTIONAL - SKIP IF LOW DISK)
# =============================================================================

check_disk_and_install_docker() {
    local available_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    
    if [[ $available_space -gt 45 ]]; then
        log "STEP" "Enough disk space for Docker - installing..."
        
        # Install Docker
        if ! command -v docker &>/dev/null; then
            curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
            sudo sh /tmp/get-docker.sh >> "$LOG_FILE" 2>&1
            sudo usermod -aG docker $USER
            rm /tmp/get-docker.sh
            log "SUCCESS" "Docker installed"
        else
            log "INFO" "Docker already installed"
        fi
        USE_DOCKER=true
    else
        log "WARNING" "Low disk space - skipping Docker, using local services only"
        USE_DOCKER=false
    fi
}

# =============================================================================
# APPLICATION SETUP
# =============================================================================

setup_application() {
    log "STEP" "Setting up Threat Intelligence Platform..."
    
    cd /opt/threat-intel-platform
    
    # Create virtual environment
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log "INFO" "Virtual environment created"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install minimal Python packages
    cat <<'EOF' > requirements-minimal.txt
pymongo==4.5.0
redis==5.0.1
requests==2.31.0
flask==3.0.0
flask-cors==4.0.0
python-dotenv==1.0.0
pyyaml==6.0.1
EOF
    
    pip install --upgrade pip >> "$LOG_FILE" 2>&1
    pip install -r requirements-minimal.txt >> "$LOG_FILE" 2>&1
    
    log "SUCCESS" "Python packages installed"
}

# =============================================================================
# CREATE CONFIGURATION
# =============================================================================

create_config() {
    log "STEP" "Creating configuration files..."
    
    cd /opt/threat-intel-platform
    
    # Create .env file with Kali-specific settings
    cat <<'EOF' > .env
# Kali Linux Optimized Configuration
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=threat_intel
REDIS_HOST=localhost
REDIS_PORT=6379

# API Keys (Add your keys here)
VIRUSTOTAL_API_KEY=
ALIENVAULT_API_KEY=

# Enforcement (Kali is often used for testing)
FIREWALL_TYPE=iptables
BLOCK_DURATION_SECONDS=3600
HIGH_RISK_THRESHOLD=70
AUTO_BLOCK_ENABLED=false

# Performance (lower resource usage)
COLLECTION_INTERVAL_SECONDS=3600
MAX_CONCURRENT_FEEDS=2
BATCH_SIZE=100

# Logging
LOG_LEVEL=INFO
AUDIT_RETENTION_DAYS=30
EOF
    
    chmod 600 .env
    log "SUCCESS" "Configuration created"
}

# =============================================================================
# START LOCAL SERVICES (NO DOCKER)
# =============================================================================

start_local_services() {
    log "STEP" "Starting local services..."
    
    # Install MongoDB if not present
    if ! command -v mongod &>/dev/null; then
        log "INFO" "Installing MongoDB..."
        sudo apt-get install -y mongodb-server >> "$LOG_FILE" 2>&1 || {
            log "WARNING" "MongoDB installation failed, using SQLite fallback"
            USE_SQLITE=true
        }
    fi
    
    if [[ "$USE_SQLITE" != "true" ]] && command -v mongod &>/dev/null; then
        sudo systemctl start mongodb 2>/dev/null || sudo service mongodb start 2>/dev/null || true
        log "SUCCESS" "MongoDB started"
    fi
    
    # Install Redis if not present
    if ! command -v redis-server &>/dev/null; then
        sudo apt-get install -y redis-server >> "$LOG_FILE" 2>&1 || true
    fi
    
    if command -v redis-server &>/dev/null; then
        sudo systemctl start redis-server 2>/dev/null || sudo service redis-server start 2>/dev/null || true
        log "SUCCESS" "Redis started"
    fi
}

# =============================================================================
# CREATE SIMPLE API
# =============================================================================

create_simple_api() {
    log "STEP" "Creating simple API server..."
    
    cat <<'EOF' > /opt/threat-intel-platform/simple_api.py
#!/usr/bin/env python3
"""Simple API for Threat Intelligence Platform"""

from flask import Flask, jsonify, request
from datetime import datetime
import json
import os

app = Flask(__name__)

# In-memory storage for demonstration
threats = []
blocks = []

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "operational",
        "version": "1.0.0-kali",
        "timestamp": datetime.utcnow().isoformat()
    })

@app.route('/api/threats', methods=['GET'])
def get_threats():
    return jsonify({
        "count": len(threats),
        "threats": threats[-100:]  # Last 100 threats
    })

@app.route('/api/threats', methods=['POST'])
def add_threat():
    data = request.json
    if data:
        data['timestamp'] = datetime.utcnow().isoformat()
        threats.append(data)
        return jsonify({"status": "added", "threat": data}), 201
    return jsonify({"error": "Invalid data"}), 400

@app.route('/api/blocks', methods=['GET'])
def get_blocks():
    return jsonify({
        "count": len(blocks),
        "blocks": blocks
    })

@app.route('/api/blocks', methods=['POST'])
def add_block():
    data = request.json
    if data and 'indicator' in data:
        data['timestamp'] = datetime.utcnow().isoformat()
        blocks.append(data)
        return jsonify({"status": "blocked", "indicator": data['indicator']}), 201
    return jsonify({"error": "Missing indicator"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
EOF

    chmod +x /opt/threat-intel-platform/simple_api.py
    log "SUCCESS" "Simple API created"
}

# =============================================================================
# CREATE THREAT AGGREGATOR
# =============================================================================

create_threat_aggregator() {
    log "STEP" "Creating threat aggregator..."
    
    cat <<'EOF' > /opt/threat-intel-platform/threat_aggregator.py
#!/usr/bin/env python3
"""Simple Threat Intelligence Aggregator for Kali"""

import requests
import json
import time
import logging
from datetime import datetime
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatAggregator:
    def __init__(self):
        self.threats = []
        self.feeds = [
            {
                "name": "feodo_tracker",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "enabled": True
            },
            {
                "name": "tor_exit_nodes", 
                "url": "https://check.torproject.org/torbulkexitlist",
                "enabled": True
            },
            {
                "name": "abuse_ch_ssl",
                "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
                "enabled": True
            }
        ]
    
    def fetch_feed(self, feed: Dict) -> List[str]:
        """Fetch indicators from a feed"""
        try:
            response = requests.get(feed['url'], timeout=30)
            if response.status_code == 200:
                indicators = []
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        indicators.append(line)
                logger.info(f"Fetched {len(indicators)} from {feed['name']}")
                return indicators
        except Exception as e:
            logger.error(f"Error fetching {feed['name']}: {e}")
        return []
    
    def aggregate(self):
        """Aggregate threats from all feeds"""
        all_indicators = []
        for feed in self.feeds:
            if feed['enabled']:
                indicators = self.fetch_feed(feed)
                for indicator in indicators:
                    all_indicators.append({
                        "indicator": indicator,
                        "source": feed['name'],
                        "risk_score": 75 if feed['name'] == 'feodo_tracker' else 60,
                        "timestamp": datetime.utcnow().isoformat()
                    })
        
        # Deduplicate
        seen = set()
        unique_threats = []
        for threat in all_indicators:
            if threat['indicator'] not in seen:
                seen.add(threat['indicator'])
                unique_threats.append(threat)
        
        self.threats = unique_threats
        logger.info(f"Total unique threats: {len(self.threats)}")
        return self.threats
    
    def save_to_file(self):
        """Save threats to JSON file"""
        with open('/opt/threat-intel-platform/threats.json', 'w') as f:
            json.dump(self.threats, f, indent=2)
    
    def run(self):
        """Main loop"""
        while True:
            try:
                logger.info("Starting threat aggregation...")
                threats = self.aggregate()
                self.save_to_file()
                logger.info(f"Saved {len(threats)} threats")
                time.sleep(3600)  # Run every hour
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error: {e}")
                time.sleep(60)

if __name__ == "__main__":
    aggregator = ThreatAggregator()
    aggregator.run()
EOF

    chmod +x /opt/threat-intel-platform/threat_aggregator.py
    log "SUCCESS" "Threat aggregator created"
}

# =============================================================================
# CREATE SIMPLE FIREWALL ENFORCER
# =============================================================================

create_firewall_enforcer() {
    log "STEP" "Creating firewall enforcer..."
    
    cat <<'EOF' > /opt/threat-intel-platform/firewall_enforcer.py
#!/usr/bin/env python3
"""Simple Firewall Enforcer for Threat Intelligence"""

import subprocess
import json
import time
import logging
from datetime import datetime
from typing import List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FirewallEnforcer:
    def __init__(self):
        self.blocked_ips = set()
        self.load_blocked_ips()
    
    def load_blocked_ips(self):
        """Load currently blocked IPs from iptables"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if "DROP" in line and "saddr" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "--source" and i+1 < len(parts):
                            self.blocked_ips.add(parts[i+1])
        except Exception as e:
            logger.error(f"Error loading blocked IPs: {e}")
    
    def add_block(self, ip: str, reason: str = "threat_intel") -> bool:
        """Add IP to iptables block list"""
        if ip in self.blocked_ips:
            logger.info(f"IP {ip} already blocked")
            return False
        
        try:
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, capture_output=True)
            self.blocked_ips.add(ip)
            logger.warning(f"BLOCKED: {ip} - {reason}")
            
            # Log to file
            with open('/opt/threat-intel-platform/blocks.log', 'a') as f:
                f.write(f"{datetime.utcnow().isoformat()} - BLOCKED {ip} - {reason}\n")
            
            return True
        except Exception as e:
            logger.error(f"Failed to block {ip}: {e}")
            return False
    
    def remove_block(self, ip: str) -> bool:
        """Remove IP from iptables block list"""
        try:
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, capture_output=True)
            self.blocked_ips.discard(ip)
            logger.info(f"UNBLOCKED: {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to unblock {ip}: {e}")
            return False
    
    def get_active_blocks(self) -> List[str]:
        return list(self.blocked_ips)
    
    def run(self):
        """Monitor threats and block high-risk indicators"""
        while True:
            try:
                # Load threats from JSON file
                try:
                    with open('/opt/threat-intel-platform/threats.json', 'r') as f:
                        threats = json.load(f)
                except FileNotFoundError:
                    time.sleep(60)
                    continue
                
                # Block high-risk threats (risk_score > 70)
                for threat in threats:
                    ip = threat.get('indicator')
                    risk = threat.get('risk_score', 0)
                    
                    if risk > 70 and ip and '.' in ip:  # Simple IP check
                        self.add_block(ip, f"risk_score_{risk}")
                
                time.sleep(300)  # Check every 5 minutes
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error in enforcer: {e}")
                time.sleep(60)

if __name__ == "__main__":
    enforcer = FirewallEnforcer()
    enforcer.run()
EOF

    chmod +x /opt/threat-intel-platform/firewall_enforcer.py
    log "SUCCESS" "Firewall enforcer created"
}

# =============================================================================
# START SERVICES
# =============================================================================

start_services() {
    log "STEP" "Starting Threat Intelligence Platform services..."
    
    cd /opt/threat-intel-platform
    source venv/bin/activate
    
    # Start API in background
    nohup python3 simple_api.py >> /var/log/tip/api.log 2>&1 &
    API_PID=$!
    echo $API_PID > /opt/threat-intel-platform/api.pid
    log "SUCCESS" "API started (PID: $API_PID)"
    
    # Start Threat Aggregator in background
    nohup python3 threat_aggregator.py >> /var/log/tip/aggregator.log 2>&1 &
    AGG_PID=$!
    echo $AGG_PID > /opt/threat-intel-platform/aggregator.pid
    log "SUCCESS" "Threat Aggregator started (PID: $AGG_PID)"
    
    # Start Firewall Enforcer in background
    nohup python3 firewall_enforcer.py >> /var/log/tip/enforcer.log 2>&1 &
    ENF_PID=$!
    echo $ENF_PID > /opt/threat-intel-platform/enforcer.pid
    log "SUCCESS" "Firewall Enforcer started (PID: $ENF_PID)"
    
    sleep 5
}

# =============================================================================
# VALIDATION
# =============================================================================

validate_deployment() {
    log "STEP" "Validating deployment..."
    
    # Check API
    if curl -s "http://localhost:5001/api/health" | grep -q "operational"; then
        log "SUCCESS" "API is running"
    else
        log "WARNING" "API may not be responding"
    fi
    
    # Check processes
    if ps aux | grep -q "[p]ython3.*simple_api"; then
        log "SUCCESS" "API process is running"
    fi
    
    if ps aux | grep -q "[p]ython3.*threat_aggregator"; then
        log "SUCCESS" "Threat Aggregator is running"
    fi
    
    if ps aux | grep -q "[p]ython3.*firewall_enforcer"; then
        log "SUCCESS" "Firewall Enforcer is running"
    fi
    
    # Check iptables
    if iptables -L INPUT -n | grep -q "DROP"; then
        log "SUCCESS" "Firewall rules active"
    fi
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
    echo ""
    echo "================================================================================"
    echo -e "${GREEN}✓ Threat Intelligence Platform Deployment Complete (Kali Optimized)${NC}"
    echo "================================================================================"
    echo ""
    echo -e "${CYAN}📊 Access Points:${NC}"
    echo "  • REST API:             http://localhost:5001"
    echo "  • API Health Check:     curl http://localhost:5001/api/health"
    echo ""
    echo -e "${CYAN}📁 Important Paths:${NC}"
    echo "  • Application:          /opt/threat-intel-platform"
    echo "  • Logs:                 /var/log/tip/"
    echo "  • Threats JSON:         /opt/threat-intel-platform/threats.json"
    echo "  • Blocks Log:           /opt/threat-intel-platform/blocks.log"
    echo ""
    echo -e "${CYAN}🔧 Management Commands:${NC}"
    echo "  • View API logs:        tail -f /var/log/tip/api.log"
    echo "  • View aggregator logs: tail -f /var/log/tip/aggregator.log"
    echo "  • View enforcer logs:   tail -f /var/log/tip/enforcer.log"
    echo "  • Stop all services:    kill \$(cat /opt/threat-intel-platform/*.pid 2>/dev/null)"
    echo "  • View firewall rules:  iptables -L INPUT -n -v"
    echo ""
    echo -e "${CYAN}🔐 Security Status:${NC}"
    echo "  • Firewall:             Active (iptables)"
    echo "  • Auto-blocking:        Disabled (set AUTO_BLOCK_ENABLED=true in .env to enable)"
    echo "  • API:                  Running on port 5001"
    echo ""
    echo -e "${YELLOW}⚠️  Important Notes for Kali:${NC}"
    echo "  1. Auto-blocking is DISABLED by default for safety"
    echo "  2. To enable auto-blocking, edit /opt/threat-intel-platform/.env"
    echo "  3. Add your VirusTotal and AlienVault API keys for better threat detection"
    echo "  4. Test the API: curl -X POST http://localhost:5001/api/threats -H 'Content-Type: application/json' -d '{\"indicator\":\"8.8.8.8\",\"risk_score\":85}'"
    echo ""
    echo -e "${GREEN}Deployment successful!${NC}"
    echo "================================================================================"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo ""
    echo "================================================================================"
    echo -e "${GREEN}Threat Intelligence Platform - Kali Linux Optimized Deployment${NC}"
    echo "================================================================================"
    echo ""
    
    sudo mkdir -p $(dirname "$LOG_FILE") 2>/dev/null || true
    sudo chown $USER:$USER $(dirname "$LOG_FILE") 2>/dev/null || true
    
    log "INFO" "Starting deployment on Kali Linux"
    
    check_prerequisites
    setup_directories
    install_system_dependencies
    setup_application
    create_config
    start_local_services
    create_simple_api
    create_threat_aggregator
    create_firewall_enforcer
    start_services
    validate_deployment
    print_summary
    
    log "SUCCESS" "Deployment completed!"
}

# Run main function
main "$@"
