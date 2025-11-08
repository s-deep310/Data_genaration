"""Create incident log table"""

def run(conn):
    conn.execute('''
    CREATE TABLE IF NOT EXISTS incident_logs (
    payload_id STRING PRIMARY KEY,
    payload TEXT ,
    source_type TEXT ,
    status TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    processed_at TEXT DEFAULT (datetime('now'))
    );
    ''')
    conn.commit()
