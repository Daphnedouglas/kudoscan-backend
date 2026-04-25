import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sqlite3

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Dynamically get the folder where main.py lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 2. Attach the database name to that folder path
DB_PATH = os.path.join(BASE_DIR, 'kudoscan_siem.db')

@app.get("/api/stats")
def get_stats():
    # Now it always looks in the exact right spot, no matter who runs it
    conn = sqlite3.connect(DB_PATH) 
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT timestamp, target_type, target_value, threat_level, recommended_action FROM incidents ORDER BY id DESC")
        table_data = [dict(row) for row in cur.fetchall()]
        
        cur.execute("SELECT COUNT(*) FROM incidents")
        total = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM incidents WHERE threat_level='High'")
        high_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM incidents WHERE threat_level='Medium'")
        medium_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM incidents WHERE threat_level='Low'")
        low_count = cur.fetchone()[0]
        
        high_pct = int((high_count / total) * 100) if total > 0 else 0
        medium_pct = int((medium_count / total) * 100) if total > 0 else 0
        low_pct = int((low_count / total) * 100) if total > 0 else 0

        cur.execute("SELECT target_type, COUNT(*) as count FROM incidents GROUP BY target_type")
        types_raw = cur.fetchall()
        target_types = [{"name": row['target_type'], "count": row['count']} for row in types_raw]
        
    except Exception as e:
        # If it fails now, it will print the exact reason in your terminal!
        print(f"🚨 DATABASE ERROR: {e}")
        table_data, target_types = [], []
        high_pct = medium_pct = low_pct = total = 0
        
    finally:
        conn.close()
    
    return {
        "table_data": table_data, 
        "threat_stats": {"high": high_pct, "medium": medium_pct, "low": low_pct},
        "target_types": target_types,
        "total": total
    }