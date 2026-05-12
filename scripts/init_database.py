#!/usr/bin/env python3
"""Initialize database with required collections and indexes"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    print("Initializing Threat Intelligence Platform database...")
    
    try:
        # Import pymongo directly
        from pymongo import MongoClient, ASCENDING, DESCENDING
    except ImportError:
        print("❌ pymongo not installed. Installing...")
        os.system("pip3 install pymongo")
        from pymongo import MongoClient, ASCENDING, DESCENDING
    
    try:
        # Connect to MongoDB
        print("Connecting to MongoDB...")
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
        
        # Test connection
        client.admin.command('ping')
        print("✓ Connected to MongoDB successfully")
        
        # Create database
        db = client['threat_intel']
        
        # Create collections
        collections = ["threat_intel", "blocking_rules", "audit_logs", "whitelist", "security_events"]
        
        print("\nCreating collections...")
        for collection in collections:
            if collection not in db.list_collection_names():
                db.create_collection(collection)
                print(f"✓ Created collection: {collection}")
            else:
                print(f"• Collection already exists: {collection}")
        
        # Create indexes
        print("\nCreating indexes for threat_intel...")
        db.threat_intel.create_index([("indicator", ASCENDING)], unique=True)
        db.threat_intel.create_index([("risk_score", DESCENDING)])
        db.threat_intel.create_index([("last_seen", DESCENDING)])
        db.threat_intel.create_index([("status", ASCENDING)])
        db.threat_intel.create_index([("severity", ASCENDING)])
        print("✓ Threat intel indexes created")
        
        print("\nCreating indexes for blocking_rules...")
        db.blocking_rules.create_index([("indicator", ASCENDING)], unique=True)
        db.blocking_rules.create_index([("expires_at", ASCENDING)])
        db.blocking_rules.create_index([("is_active", ASCENDING)])
        print("✓ Blocking rules indexes created")
        
        print("\nCreating indexes for audit_logs...")
        db.audit_logs.create_index([("timestamp", DESCENDING)])
        db.audit_logs.create_index([("action", ASCENDING)])
        db.audit_logs.create_index([("user_or_system", ASCENDING)])
        print("✓ Audit logs indexes created")
        
        print("\nCreating indexes for whitelist...")
        db.whitelist.create_index([("indicator", ASCENDING)], unique=True)
        print("✓ Whitelist indexes created")
        
        # Insert a test document to verify everything works
        print("\nTesting database with sample data...")
        test_doc = {
            "indicator": "192.168.1.100",
            "threat_type": "ip",
            "source_feeds": ["test"],
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
            "risk_score": 85,
            "severity": "high",
            "status": "active",
            "confidence": 90,
            "tags": ["test", "sample"],
            "related_indicators": [],
            "block_count": 0
        }
        
        db.threat_intel.insert_one(test_doc)
        print("✓ Sample data inserted")
        
        # Remove test document
        db.threat_intel.delete_one({"indicator": "192.168.1.100"})
        print("✓ Sample data removed")
        
        print("\n" + "="*50)
        print("✅ Database initialization complete!")
        print("="*50)
        
        # Print statistics
        print("\n📊 Database Statistics:")
        for collection in collections:
            count = db[collection].count_documents({})
            print(f"  - {collection}: {count} documents")
        
        print("\n📁 Database Info:")
        print(f"  - Database Name: {db.name}")
        print(f"  - MongoDB Version: {client.server_info()['version']}")
        
        client.close()
        
    except Exception as e:
        print(f"\n❌ Error initializing database: {e}")
        print("\nTroubleshooting tips:")
        print("1. Make sure MongoDB is installed: sudo apt install mongodb")
        print("2. Start MongoDB: sudo systemctl start mongodb")
        print("3. Check MongoDB status: sudo systemctl status mongodb")
        print("4. Install pymongo: pip3 install pymongo")
        sys.exit(1)

if __name__ == "__main__":
    main()
