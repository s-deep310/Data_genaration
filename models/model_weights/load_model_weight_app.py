import os
import sqlite3
import json
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from embedding import BertEmbedder
from data_generator import create_training_table
from model_classifier import vectorize_incidents, load_pattern_info, train_and_evaluate_models, optimize_weights


def main():
    # Define paths
    MODEL_DIR = r"C:\Users\GENAIKOLGPUSR15\Desktop\Incident_management\models\bert"
    VOCAB_PATH = os.path.join(MODEL_DIR, "vocab.txt")
    CONFIG_PATH = os.path.join(MODEL_DIR, "config.json")
    SAFETENSORS_PATH = os.path.join(MODEL_DIR, "model.safetensors")
    DB_PATH = r"C:\Users\GENAIKOLGPUSR15\Desktop\Incident_management\data\database\im_db.db"
    INC_SEV_SCALER = os.path.join(MODEL_DIR, "incident_severity_scaler.joblib")
    INC_SEV_CLASSIFIER = os.path.join(MODEL_DIR, "incident_severity_classifier.joblib")
    SEVERITY_WEIGHTS_PATH = os.path.join(MODEL_DIR, "severity_weights.json")

    # Load BERT embedder (offline, local files)
    embedder = BertEmbedder(SAFETENSORS_PATH, VOCAB_PATH, CONFIG_PATH)

    # Generate synthetic data for training (creates/overwrites training table in DB)
    create_training_table(DB_PATH, num_samples=1000)

    # Load severity rule info and encode with BERT
    pattern_info = load_pattern_info(embedder, DB_PATH)

    # Load incident JSON and labels from DB for vectorization
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT incident_json, severity_level FROM training_incidents")
    training_data = cursor.fetchall()
    conn.close()

    # Vectorize incidents: BERT embedding similarity + rules + env factor
    X, y = vectorize_incidents(training_data, embedder, pattern_info)

    # Train/test split for evaluation
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Scale features for ML stability
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train classifiers and choose best model
    best_model_name, best_model = train_and_evaluate_models(X_train_scaled, y_train, X_test_scaled, y_test)

    # Persist scaler and best classifier for inference
    joblib.dump(scaler, INC_SEV_SCALER)
    joblib.dump(best_model, INC_SEV_CLASSIFIER)

    # Optimize and save scoring weights for combining feature contributions
    optimize_weights(X, y, save_path=SEVERITY_WEIGHTS_PATH)


if __name__ == "__main__":
    main()
