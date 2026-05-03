#!/bin/bash
# MongoDB setup script for Threat Intelligence Platform

echo "Setting up MongoDB for Threat Intelligence Platform..."

# Create data directory
sudo mkdir -p /data/db
sudo chown -R mongodb:mongodb /data/db

# Start MongoDB service
sudo systemctl start mongod
sudo systemctl enable mongod

# Wait for MongoDB to start
sleep 5

# Create database and collections
mongosh <<EOF
use threat_intel

db.createCollection("threat_intel")
db.createCollection("blocking_rules")
db.createCollection("audit_logs")

// Create indexes
db.threat_intel.createIndex({ "indicator": 1 }, { unique: true })
db.threat_intel.createIndex({ "risk_score": -1 })
db.threat_intel.createIndex({ "last_seen": -1 })
db.threat_intel.createIndex({ "status": 1 })

db.blocking_rules.createIndex({ "indicator": 1 }, { unique: true })
db.blocking_rules.createIndex({ "expires_at": 1 })
db.blocking_rules.createIndex({ "is_active": 1 })

db.audit_logs.createIndex({ "timestamp": -1 })
db.audit_logs.createIndex({ "action": 1 })

print("MongoDB setup complete!")
EOF

echo "MongoDB setup finished successfully"
