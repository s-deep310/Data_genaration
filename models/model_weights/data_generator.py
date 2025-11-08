import json
import datetime
import random
import logging
import sqlite3
from import_library_weight import *

def generate_synthetic_incident(id):
    environments = ['prod', 'uat', 'dev']
    severities = ['S1', 'S2', 'S3', 'S4']
    services = ["Storage", "Sql", "KeyVault", "Network", "AppService", 
                "Compute", "Monitoring", "EventHub", "Functions"]
    levels = ["Error", "Warning", "Informational"]

    env = random.choice(environments)
    level = random.choices(levels, weights=[0.2,0.3,0.5])[0]
    service = random.choice(services)

    now = datetime.datetime.utcnow()
    random_days = random.randint(0,30)
    timestamp = (now - datetime.timedelta(days=random_days)).isoformat() + "Z"

    if level == "Error":
        messages = [
            f"{service} failure, retry limit reached",
            f"{service} authentication failed due to invalid credentials",
            f"{service} request timed out",
            f"{service} resource locked by another operation",
            f"{service} request throttled due to rate limit"
        ]
        severity_label = random.choice(['S1', 'S2'])
    elif level == "Warning":
        messages = [
            f"{service} latency above threshold",
            f"{service} nearing quota limit",
            f"{service} intermittent connectivity issues",
            f"{service} increased error rate detected",
            f"{service} resource consumption high"
        ]
        severity_label = random.choice(['S2', 'S3'])
    else:
        messages = [
            f"{service} operation succeeded",
            f"{service} scheduled maintenance upcoming",
            f"{service} configuration updated successfully",
            f"{service} health check normal",
            f"{service} routine backup completed"
        ]
        severity_label = 'S4'

    message = random.choice(messages)
    incident = {
        "properties": {"environment": env, "error": {"message": message}},
        "operationName": {"value": f"{service} Operation"},
        "status": {"value": "Failed" if level=="Error" else "Warning" if level=="Warning" else "Success"},
        "category": level,
        "timestamp": timestamp,
        "service": service,
        "severity_label": severity_label
    }
    return (id, json.dumps(incident), severity_label)


def create_training_table(DB_PATH, num_samples=1000):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS training_incidents")
    cursor.execute("""
        CREATE TABLE training_incidents (
            id TEXT PRIMARY KEY,
            incident_json TEXT NOT NULL,
            severity_level TEXT NOT NULL
        )
    """)
    for i in range(num_samples):
        incident_id = f"id_{i:05d}"
        record = generate_synthetic_incident(incident_id)
        cursor.execute("INSERT INTO training_incidents (id, incident_json, severity_level) VALUES (?, ?, ?)", record)
        if (i+1) % 100 == 0:
            conn.commit()
            logging.info(f"Inserted {i+1} synthetic incidents")
    conn.commit()
    conn.close()
