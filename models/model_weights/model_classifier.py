import json
import numpy as np
import sqlite3
from scipy.spatial.distance import cosine
from import_library_weight import *

def extract_analysis_text(incident_data):
    parts = []
    if isinstance(incident_data, dict):
        props = incident_data.get("properties", {})
        if isinstance(props, dict):
            error = props.get("error")
            if isinstance(error, dict):
                parts.append(str(error.get("message", "")))
        op = incident_data.get("operationName")
        if op:
            if isinstance(op, dict):
                parts.append(str(op.get("value", "")))
            else:
                parts.append(str(op))
        status = incident_data.get("status")
        if status:
            if isinstance(status, dict):
                parts.append(str(status.get("value", "")))
            else:
                parts.append(str(status))
        category = incident_data.get("category")
        if category:
            parts.append(str(category))
    return " ".join(filter(None, parts))

def get_environment_factor(incident_data):
    env = None
    if isinstance(incident_data, dict):
        props = incident_data.get("properties", {})
        if isinstance(props, dict):
            env = (props.get("environment") or props.get("env") or "").lower()
        if not env:
            tags = incident_data.get("tags", {})
            if isinstance(tags, dict):
                env = tags.get("Environment", "").lower()
        if not env:
            resource_id = str(incident_data.get("resourceId", "")).lower()
            if "prod-" in resource_id or "/prod/" in resource_id:
                env = "prod"
            elif "uat-" in resource_id or "/uat/" in resource_id:
                env = "uat"
            elif "dev-" in resource_id or "/dev/" in resource_id:
                env = "dev"
    return {"prod":1.2, "production":1.2, "uat":1.0, "staging":1.0, "test":1.0, "dev":0.8, "development":0.8}.get(env, 1.0)

def load_pattern_info(embedder, DB_PATH):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT pattern, base_score FROM severity_rules")
    rules = cursor.fetchall()
    conn.close()
    pattern_info = {}
    for pattern, base_score in rules:
        emb = embedder.encode(pattern.lower())
        pattern_info[pattern] = {'embedding': emb, 'base_score': base_score}
    return pattern_info

def vectorize_incidents(data, embedder, pattern_info):
    X = []
    y = []
    severity_map = {'S1':0, 'S2':1, 'S3':2, 'S4':3}
    for incident_json, label in data:
        incident_data = json.loads(incident_json)
        text = extract_analysis_text(incident_data)
        text_emb = embedder.encode(text.lower())
        max_similarity = 0
        best_rule_score = 0
        for pattern, info in pattern_info.items():
            sim = 1 - cosine(text_emb, info['embedding'])
            if sim > max_similarity:
                max_similarity = sim
                best_rule_score = info['base_score'] * get_environment_factor(incident_data)
        env_factor = get_environment_factor(incident_data)
        X.append([max_similarity, best_rule_score, env_factor])
        y.append(severity_map.get(label, 3))
    return np.array(X), np.array(y)

def train_and_evaluate_models(X_train, y_train, X_test, y_test):
    models = {}
    results = {}

    lr = LogisticRegression(max_iter=500, multi_class='multinomial')
    lr.fit(X_train, y_train)
    preds_lr = lr.predict(X_test)
    print("Logistic Regression:\n", classification_report(y_test, preds_lr))
    results['logistic_regression'] = accuracy_score(y_test, preds_lr)
    models['logistic_regression'] = lr

    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    preds_rf = rf.predict(X_test)
    print("Random Forest:\n", classification_report(y_test, preds_rf))
    results['random_forest'] = accuracy_score(y_test, preds_rf)
    models['random_forest'] = rf

    best_model_name = max(results, key=results.get)
    print(f"Best model: {best_model_name} with accuracy {results[best_model_name]:.4f}")
    return best_model_name, models[best_model_name]

def optimize_weights(X, y, save_path="severity_weights.json"):
    severity_score_map = {0: 100, 1: 75, 2: 50, 3: 25}
    y_scores = np.array([severity_score_map[label] for label in y])
    reg = LinearRegression()
    reg.fit(X, y_scores)
    weights = {
        "bert_weight": reg.coef_[0],
        "rule_weight": reg.coef_[1],
        "env_weight": reg.coef_[2],
        "intercept": reg.intercept_
    }
    print("\nOptimized weights:")
    for k, v in weights.items():
        print(f"{k}: {v:.4f}")
    with open(save_path, "w") as f:
        json.dump(weights, f, indent=2)
    return weights
