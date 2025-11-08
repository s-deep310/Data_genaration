def run(conn):
    conn.execute('''
    CREATE TABLE IF NOT EXISTS "classifier_outputs" (
        "id"	INTEGER,
        "payload_id"	STRING NOT NULL,
        "environment"	STRING,
        "severity_id"	VARCHAR,
        "bert_score"	FLOAT,
        "rule_score"	FLOAT,
        "combined_score"	FLOAT,
        "matched_pattern"	TEXT,
        "is_incident"	SMALLINT,
        "source_type"	VARCHAR,
        "payload"	TEXT,
        "processed_at"	TIMESTAMP,
        "corrective_action"	TEXT,
        "approver_id" INTEGER DEFAULT NULL,
        "approver_suggestion" TEXT DEFAULT NULL,
        "approved_at"  TEXT DEFAULT NULL,
        PRIMARY KEY("id")
    );
    ''')
    conn.commit()
