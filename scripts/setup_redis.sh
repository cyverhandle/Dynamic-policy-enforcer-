#!/bin/bash
# setup_redis.sh - Redis Setup and Configuration for Threat Intelligence Platform
# Author: TIP Development Team
# Description: Installs, configures, and secures Redis for caching and session management

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
REDIS_VERSION="7.2.3"
REDIS_PORT="6379"
REDIS_CONFIG_DIR="/etc/redis"
REDIS_DATA_DIR="/var/lib/redis"
REDIS_LOG_DIR="/var/log/redis"
REDIS_USER="redis"
REDIS_GROUP="redis"
REDIS_PASSWORD_FILE="/etc/redis/.redis_password"
MAX_MEMORY="256mb"  # Adjust based on your system
MAX_MEMORY_POLICY="allkeys-lru"

# Logging function
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Generate random password
generate_password() {
    openssl rand -base64 32 | tr -d '\n' | tr -d '=' | cut -c1-32
}

# Detect OS and package manager
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VERSION"
}

# Install Redis based on OS
install_redis() {
    log_step "Installing Redis..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y redis-server redis-tools
            ;;
        centos|rhel|fedora)
            if [[ $OS == "centos" || $OS == "rhel" ]]; then
                # Enable EPEL repository for CentOS/RHEL
                yum install -y epel-release
            fi
            yum install -y redis
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    log_info "Redis installation completed"
}

# Create Redis directories
create_directories() {
    log_step "Creating Redis directories..."
    
    # Create data directory
    if [[ ! -d $REDIS_DATA_DIR ]]; then
        mkdir -p $REDIS_DATA_DIR
        log_info "Created $REDIS_DATA_DIR"
    fi
    
    # Create log directory
    if [[ ! -d $REDIS_LOG_DIR ]]; then
        mkdir -p $REDIS_LOG_DIR
        log_info "Created $REDIS_LOG_DIR"
    fi
    
    # Set permissions
    chown -R $REDIS_USER:$REDIS_GROUP $REDIS_DATA_DIR
    chown -R $REDIS_USER:$REDIS_GROUP $REDIS_LOG_DIR
    chmod 750 $REDIS_DATA_DIR
    chmod 750 $REDIS_LOG_DIR
    
    log_info "Directory permissions configured"
}

# Generate Redis password
setup_password() {
    log_step "Setting up Redis authentication..."
    
    if [[ ! -f $REDIS_PASSWORD_FILE ]]; then
        REDIS_PASSWORD=$(generate_password)
        echo "$REDIS_PASSWORD" > $REDIS_PASSWORD_FILE
        chmod 640 $REDIS_PASSWORD_FILE
        chown $REDIS_USER:$REDIS_GROUP $REDIS_PASSWORD_FILE
        log_info "Generated new Redis password"
    else
        REDIS_PASSWORD=$(cat $REDIS_PASSWORD_FILE)
        log_info "Using existing Redis password"
    fi
    
    # Save password to environment file for application
    ENV_FILE="/opt/threat-intel-platform/.env"
    if [[ -f $ENV_FILE ]]; then
        sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" $ENV_FILE || \
        echo "REDIS_PASSWORD=$REDIS_PASSWORD" >> $ENV_FILE
    fi
    
    log_info "Redis password configured (saved to $REDIS_PASSWORD_FILE)"
}

# Configure Redis
configure_redis() {
    log_step "Configuring Redis..."
    
    REDIS_CONF="$REDIS_CONFIG_DIR/redis.conf"
    BACKUP_CONF="${REDIS_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Backup existing configuration
    if [[ -f $REDIS_CONF ]]; then
        cp $REDIS_CONF $BACKUP_CONF
        log_info "Backed up existing configuration to $BACKUP_CONF"
    fi
    
    # Create new configuration
    cat > $REDIS_CONF <<EOF
# Redis configuration for Threat Intelligence Platform
# Generated: $(date)

# Network
bind 127.0.0.1
port $REDIS_PORT
protected-mode yes
tcp-backlog 511
timeout 0
tcp-keepalive 300

# Security
requirepass $REDIS_PASSWORD
masterauth $REDIS_PASSWORD
rename-command CONFIG "CONFIG_$(generate_password | cut -c1-8)"
rename-command FLUSHDB "FLUSHDB_$(generate_password | cut -c1-8)"
rename-command FLUSHALL "FLUSHALL_$(generate_password | cut -c1-8)"

# Memory Management
maxmemory $MAX_MEMORY
maxmemory-policy $MAX_MEMORY_POLICY
maxmemory-samples 5

# Persistence (RDB + AOF for durability)
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename "dump.rdb"
dir $REDIS_DATA_DIR

# Append Only File (AOF) for durability
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
aof-use-rdb-preamble yes

# Logging
loglevel notice
logfile "$REDIS_LOG_DIR/redis-server.log"

# Performance
databases 16
always-show-logo no
set-proc-title yes
proc-title-template "{title} {listen-addr} {port}"

# Slow log
slowlog-log-slower-than 10000
slowlog-max-len 128

# Latency monitoring
latency-monitor-threshold 100

# Notifications
notify-keyspace-events Ex

# Client limits
maxclients 10000
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60

# Replication (if needed for HA)
# replicaof <masterip> <masterport>
# masteruser <username>

# Lua scripts
lua-time-limit 5000

# Cluster (disabled for single instance)
cluster-enabled no

# Slow commands logging
slowlog-log-slower-than 10000
slowlog-max-len 128

# Memory defragmentation
activedefrag yes
active-defrag-ignore-bytes 100mb
active-defrag-threshold-lower 10
active-defrag-threshold-upper 100
active-defrag-cycle-min 5
active-defrag-cycle-max 75

# TLS/SSL (optional - uncomment if using TLS)
# tls-port 6380
# tls-cert-file /etc/redis/redis.crt
# tls-key-file /etc/redis/redis.key
# tls-ca-cert-file /etc/redis/ca.crt
EOF
    
    chmod 644 $REDIS_CONF
    chown $REDIS_USER:$REDIS_GROUP $REDIS_CONF
    
    log_info "Redis configuration saved to $REDIS_CONF"
}

# Configure system limits
configure_system_limits() {
    log_step "Configuring system limits for Redis..."
    
    # Add limits configuration
    LIMITS_FILE="/etc/security/limits.d/redis.conf"
    cat > $LIMITS_FILE <<EOF
redis soft nofile 65536
redis hard nofile 65536
redis soft nproc 32768
redis hard nproc 32768
redis soft memlock unlimited
redis hard memlock unlimited
EOF
    
    # Configure sysctl for better performance
    SYSCTL_FILE="/etc/sysctl.d/99-redis.conf"
    cat > $SYSCTL_FILE <<EOF
# Redis optimizations
vm.overcommit_memory = 1
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 2048
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.ip_local_port_range = 1024 65535
EOF
    
    sysctl -p $SYSCTL_FILE
    log_info "System limits configured"
}

# Create systemd service file
create_systemd_service() {
    log_step "Creating systemd service..."
    
    SERVICE_FILE="/etc/systemd/system/redis-server.service"
    
    cat > $SERVICE_FILE <<EOF
[Unit]
Description=Redis In-Memory Data Store for Threat Intelligence Platform
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$REDIS_USER
Group=$REDIS_GROUP
ExecStart=/usr/bin/redis-server $REDIS_CONFIG_DIR/redis.conf
ExecStop=/usr/bin/redis-cli -a $REDIS_PASSWORD shutdown
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10
TimeoutStopSec=60

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=$REDIS_DATA_DIR $REDIS_LOG_DIR
ReadOnlyPaths=/etc/redis

# File descriptor limit
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_info "Systemd service created"
}

# Start and enable Redis
start_redis() {
    log_step "Starting Redis service..."
    
    systemctl enable redis-server
    systemctl start redis-server
    
    # Wait for Redis to start
    sleep 3
    
    if systemctl is-active --quiet redis-server; then
        log_info "Redis service started successfully"
    else
        log_error "Redis service failed to start"
        journalctl -u redis-server -n 20 --no-pager
        exit 1
    fi
}

# Test Redis connection
test_redis() {
    log_step "Testing Redis connection..."
    
    # Test authentication and basic operations
    if redis-cli -a "$REDIS_PASSWORD" --no-auth-warning ping | grep -q "PONG"; then
        log_info "Redis authentication successful"
    else
        log_error "Redis authentication failed"
        exit 1
    fi
    
    # Test set/get operations
    TEST_KEY="tip_test_$(date +%s)"
    if redis-cli -a "$REDIS_PASSWORD" --no-auth-warning set "$TEST_KEY" "test_value" | grep -q "OK"; then
        log_info "Redis write operation successful"
    else
        log_error "Redis write operation failed"
        exit 1
    fi
    
    if redis-cli -a "$REDIS_PASSWORD" --no-auth-warning get "$TEST_KEY" | grep -q "test_value"; then
        log_info "Redis read operation successful"
    else
        log_error "Redis read operation failed"
        exit 1
    fi
    
    # Clean up test key
    redis-cli -a "$REDIS_PASSWORD" --no-auth-warning del "$TEST_KEY" > /dev/null
    
    log_info "Redis connection test passed"
}

# Setup Redis monitoring
setup_monitoring() {
    log_step "Setting up Redis monitoring..."
    
    # Create Redis info script for monitoring
    MONITOR_SCRIPT="/usr/local/bin/redis_monitor.sh"
    cat > $MONITOR_SCRIPT <<'EOF'
#!/bin/bash
# Redis monitoring script for Prometheus/health checks

REDIS_PASSWORD=$(cat /etc/redis/.redis_password 2>/dev/null)
REDIS_CLI="redis-cli -a $REDIS_PASSWORD --no-auth-warning"

# Get Redis info
$REDIS_CLI info 2>/dev/null | grep -E "^redis_version|^uptime_in_seconds|^connected_clients|^used_memory|^used_memory_peak|^total_connections_received|^total_commands_processed|^instantaneous_ops_per_sec|^rejected_connections|^expired_keys|^evicted_keys|^keyspace_hits|^keyspace_misses"

# Output in Prometheus format
echo "# HELP redis_up Redis server health"
echo "# TYPE redis_up gauge"
if $REDIS_CLI ping 2>/dev/null | grep -q "PONG"; then
    echo "redis_up 1"
else
    echo "redis_up 0"
fi
EOF
    
    chmod +x $MONITOR_SCRIPT
    chown $REDIS_USER:$REDIS_GROUP $MONITOR_SCRIPT
    
    # Create log rotation configuration
    LOGROTATE_FILE="/etc/logrotate.d/redis"
    cat > $LOGROTATE_FILE <<EOF
$REDIS_LOG_DIR/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 redis redis
    sharedscripts
    postrotate
        systemctl kill -s USR1 redis-server
    endscript
}
EOF
    
    log_info "Redis monitoring configured"
}

# Setup Redis backup
setup_backup() {
    log_step "Setting up Redis backup..."
    
    BACKUP_SCRIPT="/usr/local/bin/redis_backup.sh"
    cat > $BACKUP_SCRIPT <<'EOF'
#!/bin/bash
# Redis backup script

BACKUP_DIR="/var/backups/redis"
RETENTION_DAYS=7
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REDIS_PASSWORD=$(cat /etc/redis/.redis_password 2>/dev/null)

# Create backup directory
mkdir -p $BACKUP_DIR

# Trigger RDB save
redis-cli -a "$REDIS_PASSWORD" --no-auth-warning save

# Copy RDB file
if [[ -f /var/lib/redis/dump.rdb ]]; then
    cp /var/lib/redis/dump.rdb $BACKUP_DIR/dump_$TIMESTAMP.rdb
    gzip $BACKUP_DIR/dump_$TIMESTAMP.rdb
    echo "Backup created: $BACKUP_DIR/dump_$TIMESTAMP.rdb.gz"
fi

# Copy AOF file
if [[ -f /var/lib/redis/appendonly.aof ]]; then
    cp /var/lib/redis/appendonly.aof $BACKUP_DIR/aof_$TIMESTAMP.aof
    gzip $BACKUP_DIR/aof_$TIMESTAMP.aof
    echo "AOF backup created: $BACKUP_DIR/aof_$TIMESTAMP.aof.gz"
fi

# Remove old backups
find $BACKUP_DIR -name "*.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup cleanup completed (retaining $RETENTION_DAYS days)"
EOF
    
    chmod +x $BACKUP_SCRIPT
    
    # Add cron job for daily backup
    CRON_FILE="/etc/cron.d/redis-backup"
    echo "0 2 * * * root /usr/local/bin/redis_backup.sh >> /var/log/redis_backup.log 2>&1" > $CRON_FILE
    
    log_info "Redis backup configured"
}

# Display final information
display_summary() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}Redis Setup Complete!${NC}"
    echo "=========================================="
    echo ""
    echo "Redis Configuration:"
    echo "  Host: 127.0.0.1"
    echo "  Port: $REDIS_PORT"
    echo "  Password: $REDIS_PASSWORD"
    echo "  Data Directory: $REDIS_DATA_DIR"
    echo "  Log Directory: $REDIS_LOG_DIR"
    echo ""
    echo "Commands:"
    echo "  Start Redis:    sudo systemctl start redis-server"
    echo "  Stop Redis:     sudo systemctl stop redis-server"
    echo "  Restart Redis:  sudo systemctl restart redis-server"
    echo "  Status Redis:   sudo systemctl status redis-server"
    echo "  Redis CLI:      redis-cli -a \"$REDIS_PASSWORD\""
    echo ""
    echo "Monitoring:"
    echo "  Health Check:   /usr/local/bin/redis_monitor.sh"
    echo "  Backup:         /usr/local/bin/redis_backup.sh"
    echo "  Logs:           journalctl -u redis-server -f"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Save the Redis password securely!${NC}"
    echo "Password saved to: $REDIS_PASSWORD_FILE"
    echo "Also added to: /opt/threat-intel-platform/.env (if exists)"
    echo ""
    echo "=========================================="
}

# Main execution
main() {
    echo ""
    echo "=========================================="
    echo "Redis Setup for Threat Intelligence Platform"
    echo "=========================================="
    echo ""
    
    check_root
    detect_os
    install_redis
    create_directories
    setup_password
    configure_redis
    configure_system_limits
    create_systemd_service
    start_redis
    test_redis
    setup_monitoring
    setup_backup
    display_summary
}

# Run main function
main
