import sqlite3
import json
import numpy as np
from scipy.spatial.distance import cosine

class SeverityRuleEngine:
    def __init__(self, db_path, embedder):
        self.db_path = db_path
        self.embedder = embedder
        self.similarity_threshold = 0.65
        self.load_rules()

    def load_rules(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT pattern, severity_level, base_score, category, description FROM severity_rules")
        self.rules = cursor.fetchall()
        conn.close()
        self.pattern_info = {}
        for pattern, sev_level, base_score, category, description in self.rules:
            embedding = self.embedder.encode(pattern.lower())
            self.pattern_info[pattern] = {
                'embedding': embedding,
                'severity_level': sev_level,
                'base_score': base_score,
                'category': category,
                'description': description
            }

    def analyze_text(self, text, incident_data, weights=None, scaler=None, classifier=None):
        text = text.lower()
        text_embedding = self.embedder.encode(text)
        matches = []
        for pattern, info in self.pattern_info.items():
            similarity = 1 - cosine(text_embedding, info['embedding'])
            if similarity >= self.similarity_threshold:
                matches.append({
                    'pattern': pattern,
                    'similarity': similarity,
                    'severity_level': info['severity_level'],
                    'base_score': info['base_score'],
                    'category': info['category']
                })
        if not matches:
            return {
                "severity_level": "S4",
                "bert_score": 0.0,
                "rule_score": 10.0,
                "combined_score": 10.0,
                "matched_pattern": None,
                "matched_keywords": [],
                "all_matches": []
            }
        matches.sort(key=lambda x: x['similarity'], reverse=True)
        best_match = matches[0]
        env_factor, _ = self.get_environment_factor(incident_data)
        bert_score = best_match['similarity']
        rule_score = float(best_match['base_score'])
        adjusted_rule_score = rule_score * env_factor

        # ML-based or heuristic severity
        if classifier is not None and scaler is not None and weights is not None:
            features = np.array([[bert_score, adjusted_rule_score, env_factor]])
            features_scaled = scaler.transform(features)
            severity_class = classifier.predict(features_scaled)[0]
            combined_score = (
                weights['bert_weight'] * bert_score +
                weights['rule_weight'] * adjusted_rule_score +
                weights['env_weight'] * env_factor +
                weights.get('intercept', 0)
            )
            severity_map = {0: 'S1', 1: 'S2', 2: 'S3', 3: 'S4'}
            final_severity = severity_map.get(severity_class, 'S4')
        else:
            # Heuristic
            bert_weight = weights['bert_weight'] if weights else 0.4
            rule_weight = weights['rule_weight'] if weights else 0.6
            combined_score = (
                (bert_score * 100 * bert_weight) + (adjusted_rule_score * rule_weight)
            )
            if combined_score >= 80:
                final_severity = "S1"
            elif combined_score >= 60:
                final_severity = "S2"
            elif combined_score >= 40:
                final_severity = "S3"
            else:
                final_severity = "S4"

        matched_keywords = [
            keyword for keyword in text.split()
            if any(pattern.lower() in keyword for pattern in self.pattern_info.keys())
        ]
        return {
            "severity_level": final_severity,
            "bert_score": bert_score,
            "rule_score": adjusted_rule_score,
            "combined_score": combined_score,
            "matched_pattern": best_match['pattern'],
            "matched_keywords": matched_keywords,
            "all_matches": matches[:3]
        }

    def get_environment_factor(self, incident_data):
        env = None
        if isinstance(incident_data, dict):
            props = incident_data.get("properties", {})
            env = (props.get("environment") or props.get("env") or "").lower() if isinstance(props, dict) else None
            if not env:
                tags = incident_data.get("tags", {})
                if isinstance(tags, dict):
                    env = tags.get("Environment", "").lower()
            if not env:
                resource_id = str(incident_data.get("resourceId", ""))
                if "prod-" in resource_id or "/prod/" in resource_id:
                    env = "prod"
                elif "uat-" in resource_id or "/uat/" in resource_id:
                    env = "uat"
                elif "dev-" in resource_id or "/dev/" in resource_id:
                    env = "dev"
            if env in ["prod", "production"]:
                return 1.2, "prod"
            elif env in ["uat", "staging", "test"]:
                return 1.0, "uat"
            elif env in ["dev", "development"]:
                return 0.8, "dev"
        return 1.0, "unknown"

    def extract_analysis_text(self, incident_data):
        analysis_text = []
        if isinstance(incident_data, dict):
            props = incident_data.get("properties", {})
            if isinstance(props, dict):
                error = props.get("error", {})
                if isinstance(error, dict):
                    analysis_text.append(str(error.get("message", "")))
            op_name = incident_data.get("operationName", "")
            if isinstance(op_name, dict):
                analysis_text.append(str(op_name.get("value", "")))
            else:
                analysis_text.append(str(op_name))
            status = incident_data.get("status", "")
            if isinstance(status, dict):
                analysis_text.append(str(status.get("value", "")))
            else:
                analysis_text.append(str(status))
            category = incident_data.get("category", "")
            analysis_text.append(str(category))
        return " ".join(filter(None, analysis_text))
