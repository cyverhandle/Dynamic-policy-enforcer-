#!/usr/bin/env python3
"""Initialize database with required collections and indexes"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database.mongo_client import MongoDBClient
from src.config.settings import config

def main():
    print("Initializing Threat Intelligence Platform database...")
    
    client = MongoDBClient(
        config.database.mongodb_uri,
        config.database.mongodb_db
    )
    
    # Create collections
    client.db.create_collection("threat_intel")
    client.db.create_collection("blocking_rules")
    client.db.create_collection("audit_logs")
    
    print("Database initialization complete!")

if __name__ "__main__":
    main()
