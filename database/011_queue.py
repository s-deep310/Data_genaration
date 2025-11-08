def run(conn):
    conn.execute('''
    CREATE TABLE IF NOT EXISTS "queue" (
        "id"	TEXT,
        "data"	TEXT NOT NULL,
        "status"	TEXT DEFAULT 'pending',
        "created_at"	TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        "processed_at"	TEXT DEFAULT NULL,
        "consumer_id"	TEXT,
        PRIMARY KEY("id")
    );
    ''')
    conn.commit()
