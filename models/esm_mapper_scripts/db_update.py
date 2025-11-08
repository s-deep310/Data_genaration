import sqlite3
import json

class SeverityDBUpdater:
    def __init__(self, db_path):
        self.db_path = db_path

    def process_incidents(self, rule_engine, scaler=None, classifier=None, weights=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT payload_id, payload FROM incident_logs ")
        incidents = cursor.fetchall()
        print(f"Processing {len(incidents)} incidents...")

        for idx, (payload_id, payload) in enumerate(incidents, 1):
            try:
                incident_data = json.loads(payload)
            except Exception as e:
                print(f"Skipping incident {payload_id}: invalid JSON - {e}")
                continue
            analysis_text = rule_engine.extract_analysis_text(incident_data)
            severity_info = rule_engine.analyze_text(
                analysis_text.strip(), incident_data, weights=weights, scaler=scaler, classifier=classifier
            )
            environment = incident_data.get("properties", {}).get("environment", "unknown")
            cursor.execute("""
                INSERT INTO enhanced_severity_mappings 
                ( payload_id , severity_id, bert_score, rule_score, combined_score, matched_pattern, environment, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                'payload_id',
                severity_info["severity_level"],
                float(severity_info["bert_score"]),
                float(severity_info["rule_score"]),
                float(severity_info["combined_score"]),
                severity_info["matched_pattern"],
                environment,
                payload
            ))

            cursor.execute("UPDATE incident_logs SET processed_at = CURRENT_TIMESTAMP WHERE payload_id = ?", (payload_id))
            
            if idx % 100 == 0:
                conn.commit()
                print(f"Processed {idx} incidents...")
        conn.commit()
        conn.close()
