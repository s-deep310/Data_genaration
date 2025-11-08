import os
import joblib
import json
from incident_db.models.incident_log import IncidentLogsModel
from embedding import BertEmbedder
from severity_model import SeverityRuleEngine
from db_update import SeverityDBUpdater
import sqlite3 

# Set model and database paths
MODEL_DIR = r"C:\Users\GENAIKOLGPUSR15\Desktop\Incident_management\models\bert"
VOCAB_PATH = os.path.join(MODEL_DIR, "vocab.txt")
CONFIG_PATH = os.path.join(MODEL_DIR, "config.json")
SAFETENSORS_PATH = os.path.join(MODEL_DIR, "model.safetensors")
DB_PATH = r"C:\Users\GENAIKOLGPUSR15\Desktop\Incident_management\data\database\im_db.db"
INC_SEV_SCALER = os.path.join(MODEL_DIR, "incident_severity_scaler.joblib")
INC_SEV_CLASSIFIER = os.path.join(MODEL_DIR, "incident_severity_classifier.joblib")
SEVERITY_WEIGHTS_JSON = os.path.join(MODEL_DIR, "severity_weights.json")

def main():
    logs = IncidentLogsModel.all()
    print(logs)
    # Initialize the BERT embedder with local model files
    embedder = BertEmbedder(SAFETENSORS_PATH, VOCAB_PATH, CONFIG_PATH)
    # Initialize severity rule engine with DB and embedder
    rule_engine = SeverityRuleEngine(DB_PATH, embedder)

    # Attempt to load ML models and weights
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

    # Initialize DB updater and process unprocessed incidents
    updater = SeverityDBUpdater(DB_PATH)
    # updater.process_incidents(rule_engine, scaler, classifier, weights)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info('enhanced_severity_mappings')")
    ddl=cursor.fetchall()
    print(DB_PATH)

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM incident_logs WHERE processed_at IS NULL")
    unprocessed_count = cursor.fetchone()[0]
    print(f"Unprocessed incidents in DB at runtime: {unprocessed_count}")

if __name__ == "__main__":
    main()
