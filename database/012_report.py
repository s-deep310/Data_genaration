def run(conn):
    conn.execute('''
    CREATE TABLE IF NOT EXISTS "report" (
        "id"	TEXT,
        "root_cause"	TEXT DEFAULT NULL,
        "environment"	TEXT DEFAULT NULL,
        "severity"      TEXT DEFAULT NULL,
        "summary"       TEXT DEFAULT NULL,
        "recommendation" TEXT DEFAULT NULL,
        "consumer_id"	TEXT,
        "created_at"	TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY("id")
    );
    ''')
    conn.commit()
