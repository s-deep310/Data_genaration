"""
System Performance Metrics Generator
Generates realistic system performance metrics linked to incident logs and alert messages
with best, good, and worst case scenarios. Produces SQLite tables and JSON datasets.

Author: AI Assistant
Date: November 5, 2025
"""

import sqlite3
import json
import uuid
import random
from datetime import datetime, timedelta


# Database configuration
DB_PATH = "Cloud_Infrastructure.db"


class MetricsEnvironmentConfig:
    """Environment and service metric configuration."""

    def __init__(self):
        self.environments = {
            "prod": {
                "subscription_id": str(uuid.uuid4()),
                "subscription_name": "Production",
                "allowed_regions": ["eastus", "westeurope", "southeastasia"],
                "resource_prefix": "prod",
                "tags": {
                    "Environment": "Production",
                    "CostCenter": "IT-Production",
                    "DataClassification": "Confidential",
                    "BusinessCriticality": "Mission-Critical"
                }
            },
            "uat": {
                "subscription_id": str(uuid.uuid4()),
                "subscription_name": "UAT",
                "allowed_regions": ["eastus2", "westus2"],
                "resource_prefix": "uat",
                "tags": {
                    "Environment": "UAT",
                    "CostCenter": "IT-Testing",
                    "DataClassification": "Internal",
                    "BusinessCriticality": "Important"
                }
            },
            "dev": {
                "subscription_id": str(uuid.uuid4()),
                "subscription_name": "Development",
                "allowed_regions": ["eastus2", "westus2"],
                "resource_prefix": "dev",
                "tags": {
                    "Environment": "Development",
                    "CostCenter": "IT-Development",
                    "DataClassification": "Internal",
                    "BusinessCriticality": "Low"
                }
            }
        }

        self.services = {
            "Microsoft.Compute/virtualMachines": {
                "metrics": {
                    "Percentage CPU": {"threshold": 85, "unit": "Percent", "aggregation": "Average"},
                    "Memory Usage": {"threshold": 75, "unit": "Percent", "aggregation": "Average"},
                    "Disk Read Bytes": {"threshold": 150000000, "unit": "BytesPerSecond", "aggregation": "Total"},
                    "Disk Write Bytes": {"threshold": 150000000, "unit": "BytesPerSecond", "aggregation": "Total"}
                }
            },
            "Microsoft.Sql/servers/databases": {
                "metrics": {
                    "cpu_percent": {"threshold": 90, "unit": "Percent", "aggregation": "Average"},
                    "storage_percent": {"threshold": 80, "unit": "Percent", "aggregation": "Maximum"},
                    "deadlocks": {"threshold": 5, "unit": "Count", "aggregation": "Total"},
                    "queries_per_second": {"threshold": 200, "unit": "Count", "aggregation": "Average"}
                }
            },
            "Microsoft.Web/sites": {
                "metrics": {
                    "Http5xx": {"threshold": 50, "unit": "Count", "aggregation": "Total"},
                    "ResponseTime": {"threshold": 5, "unit": "Seconds", "aggregation": "Average"},
                    "CpuTime": {"threshold": 120, "unit": "Seconds", "aggregation": "Total"},
                    "MemoryWorkingSet": {"threshold": 1000000000, "unit": "Bytes", "aggregation": "Average"}
                }
            },
            "Microsoft.Storage/storageAccounts": {
                "metrics": {
                    "UsedCapacity": {"threshold": 900000000000, "unit": "Bytes", "aggregation": "Average"},
                    "Transactions": {"threshold": 100000, "unit": "Count", "aggregation": "Total"},
                    "SuccessE2ELatency": {"threshold": 1000, "unit": "Milliseconds", "aggregation": "Average"},
                    "Availability": {"threshold": 99, "unit": "Percent", "aggregation": "Average"}
                }
            },
            "Microsoft.KeyVault/vaults": {
                "metrics": {
                    "ServiceApiLatency": {"threshold": 1000, "unit": "Milliseconds", "aggregation": "Average"},
                    "ServiceApiHit": {"threshold": 10000, "unit": "Count", "aggregation": "Total"},
                    "ServiceApiResult": {"threshold": 50, "unit": "Count", "aggregation": "Total"}
                }
            }
        }

    def get_resource_id(self, service, env):
        subscription_id = self.environments[env]["subscription_id"]
        region = random.choice(self.environments[env]["allowed_regions"])
        rg_name = f"{self.environments[env]['resource_prefix']}-rg-{region}"
        resource_name = f"{self.environments[env]['resource_prefix']}-{service.split('/')[-1]}-{random.randint(100,999)}"
        return f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/{service}/{resource_name}"


class SystemPerformanceMetricsGenerator:
    """Generates system performance metric records with realistic distributions"""

    def __init__(self):
        self.config = MetricsEnvironmentConfig()

    def generate_metric_record(self, env, scenario_type="normal"):
        service = random.choice(list(self.config.services.keys()))
        metric_name = random.choice(list(self.config.services[service]["metrics"].keys()))
        metric_cfg = self.config.services[service]["metrics"][metric_name]
        threshold = metric_cfg["threshold"]
        unit = metric_cfg["unit"]
        aggregation = metric_cfg["aggregation"]

        resource_id = self.config.get_resource_id(service, env)

        # Choose value based on scenario for realistic distribution
        if scenario_type == "best":
            # Optimal metrics: mostly well below thresholds
            if unit == "Percent":
                value = random.uniform(threshold * 0.3, threshold * 0.7)
            else:
                value = threshold * random.uniform(0.3, 0.7)
            alert = False
        elif scenario_type == "good":
            # Slightly above threshold occasionally
            if random.random() < 0.15:
                # Alert condition
                value = threshold * random.uniform(1.05, 1.3)
                alert = True
            else:
                if unit == "Percent":
                    value = random.uniform(threshold * 0.7, threshold)
                else:
                    value = threshold * random.uniform(0.7, 1)
                alert = False
        elif scenario_type == "worst":
            # Frequently over threshold (alerts common)
            if random.random() < 0.7:
                value = threshold * random.uniform(1.3, 2)
                alert = True
            else:
                if unit == "Percent":
                    value = random.uniform(threshold * 0.8, threshold * 1.3)
                else:
                    value = threshold * random.uniform(0.8, 1.3)
                alert = False
        else:
            # Normal distribution
            value = threshold * random.uniform(0.5, 1.5)
            alert = value > threshold

        metric_record = {
            "record_id": str(uuid.uuid4()),
            "timestamp": (datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))).isoformat() + "Z",
            "environment": env.upper(),
            "subscription_id": self.config.environments[env]["subscription_id"],
            "service": service,
            "resource_id": resource_id,
            "metric_name": metric_name,
            "metric_value": round(value, 2),
            "metric_unit": unit,
            "aggregation": aggregation,
            "threshold": threshold,
            "alert_active": alert,
            "scenario_type": scenario_type,
            "tags": self.config.environments[env]["tags"]
        }
        return metric_record

def create_tables(conn):
    """Creates all required tables"""
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_metrics (
            record_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            environment TEXT NOT NULL,
            subscription_id TEXT NOT NULL,
            service TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            metric_value REAL NOT NULL,
            metric_unit TEXT,
            aggregation TEXT,
            threshold REAL,
            alert_active INTEGER,
            scenario_type TEXT,
            tags TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_metrics_best AS SELECT * FROM system_metrics WHERE 0;
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_metrics_good AS SELECT * FROM system_metrics WHERE 0;
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_metrics_worst AS SELECT * FROM system_metrics WHERE 0;
    """)

    conn.commit()


def generate_metrics_data(total_records=1000):
    generator = SystemPerformanceMetricsGenerator()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    create_tables(conn)

    env_distribution = {
        "prod": int(total_records * 0.5),
        "uat": int(total_records * 0.3),
        "dev": int(total_records * 0.2)
    }

    scenarios = ["best", "good", "worst"]

    print("Starting generation of system metrics data...")
    print(f"Total records per scenario: {total_records}")
    print(f"Environment distribution: {env_distribution}")

    all_records = []
    scenario_records = {"best": [], "good": [], "worst": []}

    for scenario in scenarios:
        print(f"\nGenerating {scenario.upper()} scenario records.")
        for env, count in env_distribution.items():
            for _ in range(count):
                metric = generator.generate_metric_record(env, scenario)
                alert_active_int = 1 if metric["alert_active"] else 0
                tags_json = json.dumps(metric["tags"])

                cursor.execute("""
                    INSERT INTO system_metrics (
                        record_id, timestamp, environment, subscription_id, service,
                        resource_id, metric_name, metric_value, metric_unit,
                        aggregation, threshold, alert_active, scenario_type, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    metric["record_id"],
                    metric["timestamp"],
                    metric["environment"],
                    metric["subscription_id"],
                    metric["service"],
                    metric["resource_id"],
                    metric["metric_name"],
                    metric["metric_value"],
                    metric["metric_unit"],
                    metric["aggregation"],
                    metric["threshold"],
                    alert_active_int,
                    scenario,
                    tags_json
                ))

                all_records.append(metric)
                scenario_records[scenario].append(metric)

        # Bulk insert scenario records table
        sel = f"system_metrics_{scenario}"
        for m in scenario_records[scenario]:
            alert_active_int = 1 if m["alert_active"] else 0
            tags_json = json.dumps(m["tags"])
            cursor.execute(f"""
                INSERT INTO {sel} (
                    record_id, timestamp, environment, subscription_id, service,
                    resource_id, metric_name, metric_value, metric_unit,
                    aggregation, threshold, alert_active, scenario_type, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                m["record_id"], m["timestamp"], m["environment"], m["subscription_id"], m["service"],
                m["resource_id"], m["metric_name"], m["metric_value"], m["metric_unit"],
                m["aggregation"], m["threshold"], alert_active_int, m["scenario_type"], tags_json
            ))

        conn.commit()
        print(f"Inserted {len(scenario_records[scenario])} records into {sel}.")

    # Export JSON files
    print("\nExporting JSON files...")
    json_files = {
        "system_metrics_all.json": all_records,
        "system_metrics_best.json": scenario_records["best"],
        "system_metrics_good.json": scenario_records["good"],
        "system_metrics_worst.json": scenario_records["worst"]
    }
    for filename, data in json_files.items():
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Created {filename} with {len(data)} records.")

    conn.close()
    print("\nData generation complete.")


if __name__ == "__main__":
    generate_metrics_data(1000)
