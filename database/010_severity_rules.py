def run(conn):
    conn.execute('''
    CREATE TABLE IF NOT EXISTS "severity_rules" (
        "rule_id"	INTEGER,
        "pattern"	TEXT NOT NULL,
        "severity_level"	TEXT NOT NULL,
        "base_score"	REAL NOT NULL,
        "category"	TEXT,
        "description"	TEXT,
        "environment"	TEXT,
        UNIQUE("pattern","severity_level","environment"),
        PRIMARY KEY("rule_id" AUTOINCREMENT)
    );
    ''')
    conn.commit()
