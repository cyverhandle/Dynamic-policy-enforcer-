
#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform - Main Orchestrator
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import signal
import time
import threading
from datetime import datetime

# Now import from config
try:
    from config.settings import config
    print("✓ Config imported successfully")
except ImportError as e:
    print(f"✗ Config import error: {e}")
    # Create a simple config if import fails
    class SimpleConfig:
        class Database:
            mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
            mongodb_db = os.getenv("MONGODB_DB", "threat_intel")
        database = Database()
    config = SimpleConfig()
    print("✓ Using fallback configuration")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatIntelligencePlatform:
    """Main orchestration class for TIP"""
    
    def __init__(self):
        self.running = False
        self.db = None
        
        # Try to connect to MongoDB
        try:
            from pymongo import MongoClient
            self.mongo_client = MongoClient(config.database.mongodb_uri)
            self.db = self.mongo_client[config.database.mongodb_db]
            logger.info("Connected to MongoDB")
        except Exception as e:
            logger.warning(f"MongoDB not available: {e}")
            self.db = None
    
    def start(self):
        """Start the platform"""
        self.running = True
        logger.info("Starting Threat Intelligence Platform")
        logger.info("API will be available at http://localhost:5001")
        
        # Import and run the API
        try:
            from src.main_working import app
            app.run(host='0.0.0.0', port=5001, debug=False)
        except ImportError:
            logger.error("Could not import main_working module")
            # Fallback to simple API
            self.run_simple_api()
    
    def run_simple_api(self):
        """Run a simple API as fallback"""
        from flask import Flask, jsonify
        
        app = Flask(__name__)
        
        @app.route('/api/health', methods=['GET'])
        def health():
            return jsonify({
                'status': 'operational',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        @app.route('/api/threats', methods=['GET'])
        def get_threats():
            threats = []
            if self.db:
                threats = list(self.db.threat_intel.find({}, {'_id': 0}).limit(100))
            return jsonify({'count': len(threats), 'threats': threats})
        
        logger.info("Starting API server on port 5001")
        app.run(host='0.0.0.0', port=5001, debug=False)
    
    def stop(self):
        """Stop the platform"""
        logger.info("Shutting down...")
        self.running = False

def main():
    platform = ThreatIntelligencePlatform()
    try:
        platform.start()
    except KeyboardInterrupt:
        platform.stop()

if __name__ == "__main__":
    main()
