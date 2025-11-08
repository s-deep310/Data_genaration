import os
import joblib
import json
from datetime import datetime

import sys
import os
from pathlib import Path

print (Path(__file__))
# Add models directory (parent of database folder) to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

print (BASE_DIR)

from embedding import BertEmbedder
from severity_model import SeverityRuleEngine
from incident_db.db.connection import get_connection  
from incident_db.models.incident_log import IncidentLogsModel
from incident_db.models.classifier_output import ClassifierOutputsModel
import sys
import os
from pathlib import Path



def main():
    MODEL_DIR = r"C:\Users\GENAIKOLGPUSR15\Desktop\Incident_management\ai_models\bert"
    VOCAB_PATH = os.path.join(MODEL_DIR, "vocab.txt")
    CONFIG_PATH = os.path.join(MODEL_DIR, "config.json")
    SAFETENSORS_PATH = os.path.join(MODEL_DIR, "model.safetensors")
    DB_PATH = r"C:\Users\GENAIKOLGPUSR15\Desktop\Incident_management\incident_db\data\incident_iq.db"
    INC_SEV_SCALER = os.path.join(MODEL_DIR, "incident_severity_scaler.joblib")
    INC_SEV_CLASSIFIER = os.path.join(MODEL_DIR, "incident_severity_classifier.joblib")
    SEVERITY_WEIGHTS_JSON = os.path.join(MODEL_DIR, "severity_weights.json")

    # Initialize BERT embedder and rule engine
    embedder = BertEmbedder(SAFETENSORS_PATH, VOCAB_PATH, CONFIG_PATH)
    rule_engine = SeverityRuleEngine(DB_PATH, embedder)

    # Load ML models and weights if available
    try:
        scaler = joblib.load(INC_SEV_SCALER)
        classifier = joblib.load(INC_SEV_CLASSIFIER)
        with open(SEVERITY_WEIGHTS_JSON, 'r') as f:
            weights = json.load(f)
        print("Using ML-based severity classification")
    except Exception as e:
        scaler = None
        classifier = None
        weights = {
            'bert_weight': 0.35,
            'rule_weight': 0.45,
            'env_weight': 0.20,
            'intercept': 0.0
        }
        print(f"ML models not found, using rule-based classification. Reason: {str(e)}")

    # Open DB connection
    conn = get_connection()
    incident_model = IncidentLogsModel(conn)
    classifier_model = ClassifierOutputsModel(conn)

    # Fetch unprocessed incidents
    unprocessed_incidents = incident_model.find_unprocessed()
    print(f"Processing {len(unprocessed_incidents)} unprocessed incidents...")

    for incident in unprocessed_incidents:
        payload_id = incident['payload_id']
        payload = incident['payload']
        try:
            incident_data = json.loads(payload)
        except Exception as e:
            print(f"Skipping incident {payload_id}: invalid JSON - {e}")
            # Optionally mark as processed or skipped here
            continue

        # Extract text and analyze severity
        analysis_text = rule_engine.extract_analysis_text(incident_data)
        severity_info = rule_engine.analyze_text(
            analysis_text.strip(), incident_data,
            weights=weights, scaler=scaler, classifier=classifier
        )

        environment = incident_data.get("properties", {}).get("environment", "unknown")
        print(severity_info)

        # Insert or update classifier_outputs table
        insert_fields = {
            'payload_id': payload_id,
            'severity_id': severity_info["severity_level"],
            'bert_score': float(severity_info["bert_score"]),
            'rule_score': float(severity_info["rule_score"]),
            'combined_score': float(severity_info["combined_score"]),
            'matched_pattern': severity_info["matched_pattern"],
            'environment': environment,
            'payload': payload,
            'processed_at': datetime.now().isoformat(timespec='seconds')
        }

        # Upsert logic: check if row exists
        existing = classifier_model.find(payload_id)
        if existing:
            classifier_model.update_by_payload_id(payload_id, insert_fields)
        else:
            # Remove id since it is autoincremented primary key
            if 'id' in insert_fields:
                insert_fields.pop('id')
            columns = ', '.join(insert_fields.keys())
            placeholders = ', '.join('?' for _ in insert_fields)
            sql = f"INSERT INTO {classifier_model.table} ({columns}) VALUES ({placeholders})"
            classifier_model.conn.execute(sql, tuple(insert_fields.values()))
            classifier_model.conn.commit()

        # Update incident_logs processed_at to mark processed
        incident_model.update(payload_id, {'processed_at': datetime.now().isoformat(timespec='seconds')})

    conn.close()

if __name__ == "__main__":
    main()
