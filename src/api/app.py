"""
REST API for SOC Analysts to interact with the platform
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import logging

from ..database.mongo_client import MongoDBClient
from ..enforcer.policy_enforcer import FirewallEnforcer
from ..enforcer.rollback_manager import RollbackManager
from ..config.settings import config

app = Flask(__name__)
CORS(app)
logger = logging.getLogger(__name__)

# Initialize components
db = MongoDBClient(config.database.mongodb_uri, config.database.mongodb_db)
enforcer = FirewallEnforcer()
rollback_manager = RollbackManager(enforcer)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "mongodb": "connected",
            "redis": "connected",
            "firewall": enforcer.firewall_type
        }
    })

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get threat intelligence with filtering"""
    min_risk = request.args.get('min_risk', 0, type=int)
    threat_type = request.args.get('type', None)
    limit = request.args.get('limit', 100, type=int)
    
    query = {"risk_score": {"$gte": min_risk}}
    if threat_type:
        query["threat_type"] = threat_type
    
    threats = list(db.db.threat_intel.find(query).sort("risk_score", -1).limit(limit))
    
    # Convert ObjectId to string
    for threat in threats:
        threat['_id'] = str(threat['_id'])
    
    return jsonify({
        "count": len(threats),
        "threats": threats
    })

@app.route('/api/threats/<indicator>', methods=['GET'])
def get_threat(indicator):
    """Get specific threat indicator"""
    threat = db.db.threat_intel.find_one({"indicator": indicator})
    
    if not threat:
        return jsonify({"error": "Threat not found"}), 404
    
    threat['_id'] = str(threat['_id'])
    return jsonify(threat)

@app.route('/api/blocks', methods=['GET'])
def get_blocks():
    """Get active blocks"""
    blocks = enforcer.get_active_blocks()
    return jsonify({
        "count": len(blocks),
        "blocks": blocks
    })

@app.route('/api/blocks', methods=['POST'])
def add_block():
    """Manually add a block"""
    data = request.json
    
    if not data or 'indicator' not in data:
        return jsonify({"error": "Missing indicator"}), 400
    
    indicator = data['indicator']
    reason = data.get('reason', 'manual_block')
    duration = data.get('duration_seconds', None)
    
    success = enforcer.manual_block(indicator, reason, duration)
    
    if success:
        return jsonify({
            "status": "success",
            "message": f"Blocked {indicator}",
            "indicator": indicator
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"Failed to block {indicator}"
        }), 500

@app.route('/api/blocks/<indicator>', methods=['DELETE'])
def remove_block(indicator):
    """Manually remove a block"""
    data = request.json or {}
    reason = data.get('reason', 'manual_removal')
    
    success = enforcer.manual_unblock(indicator, reason)
    
    if success:
        return jsonify({
            "status": "success",
            "message": f"Unblocked {indicator}"
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"Failed to unblock {indicator}"
        }), 500

@app.route('/api/rollback/<indicator>', methods=['POST'])
def rollback_indicator(indicator):
    """Rollback a block for a specific indicator"""
    data = request.json or {}
    reason = data.get('reason', 'rollback')
    
    # Simulate first to check
    simulation = rollback_manager.simulate_rollback(indicator)
    
    if not simulation.get('can_rollback', False):
        return jsonify({
            "status": "warning",
            "message": simulation.get('reason', 'Cannot rollback'),
            "simulation": simulation
        }), 400
    
    success = rollback_manager.rollback_rule(indicator, reason)
    
    if success:
        return jsonify({
            "status": "success",
            "message": f"Rolled back block for {indicator}",
            "simulation": simulation
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"Failed to rollback {indicator}"
        }), 500

@app.route('/api/audit', methods=['GET'])
def get_audit_logs():
    """Get audit logs for compliance"""
    limit = request.args.get('limit', 100, type=int)
    action = request.args.get('action', None)
    
    logs = db.get_audit_logs(limit=limit, action=action)
    
    return jsonify({
        "count": len(logs),
        "logs": [{
            "timestamp": log.timestamp.isoformat(),
            "action": log.action,
            "indicator": log.indicator,
            "user": log.user_or_system,
            "details": log.details
        } for log in logs]
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get platform statistics"""
    # Get counts
    total_threats = db.db.threat_intel.count_documents({})
    active_threats = db.db.threat_intel.count_documents({"status": "active"})
    high_risk = db.db.threat_intel.count_documents({"risk_score": {"$gte": 70}})
    critical_risk = db.db.threat_intel.count_documents({"risk_score": {"$gte": 90}})
    active_blocks = db.db.blocking_rules.count_documents({"is_active": True})
    
    # Get top sources
    pipeline = [
        {"$unwind": "$source_feeds"},
        {"$group": {"_id": "$source_feeds", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    top_sources = list(db.db.threat_intel.aggregate(pipeline))
    
    return jsonify({
        "total_threats": total_threats,
        "active_threats": active_threats,
        "high_risk_count": high_risk,
        "critical_risk_count": critical_risk,
        "active_blocks": active_blocks,
        "top_threat_sources": [
            {"feed": s["_id"], "count": s["count"]} for s in top_sources
        ],
        "last_update": datetime.utcnow().isoformat()
    })

@app.route('/api/reports/daily', methods=['GET'])
def get_daily_report():
    """Generate daily report"""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Get today's statistics
    today_threats = db.db.threat_intel.count_documents({
        "first_seen": {"$gte": today_start}
    })
    
    today_blocks = db.db.audit_logs.count_documents({
        "action": "block_added",
        "timestamp": {"$gte": today_start}
    })
    
    false_positives = db.db.audit_logs.count_documents({
        "action": "manual_unblock",
        "timestamp": {"$gte": today_start}
    })
    
    # Get top feeds for today
    pipeline = [
        {"$match": {"first_seen": {"$gte": today_start}}},
        {"$unwind": "$source_feeds"},
        {"$group": {"_id": "$source_feeds", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    top_feeds = list(db.db.threat_intel.aggregate(pipeline))
    
    report = {
        "date": today_start.date().isoformat(),
        "total_threats": today_threats,
        "high_risk_count": db.db.threat_intel.count_documents({
            "first_seen": {"$gte": today_start},
            "risk_score": {"$gte": 70}
        }),
        "critical_risk_count": db.db.threat_intel.count_documents({
            "first_seen": {"$gte": today_start},
            "risk_score": {"$gte": 90}
        }),
        "blocks_applied": today_blocks,
        "blocks_removed": db.db.audit_logs.count_documents({
            "action": "block_removed",
            "timestamp": {"$gte": today_start}
        }),
        "false_positives": false_positives,
        "top_feeds": {f["_id"]: f["count"] for f in top_feeds}
    }
    
    return jsonify(report)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
