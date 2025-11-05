"""
Cloud Infrastructure Incident Log Generator
AI Agent for Cloud Infrastructure Incident Management

This script generates realistic incident logs for Azure cloud infrastructure
with three scenario types: BEST, GOOD, and WORST cases.

Outputs:
- 1 SQLite database with 4 tables (all, best, good, worst)
- 4 JSON files with corresponding data

Author: AI Assistant
Date: November 5, 2025
"""

import sqlite3
import json
import uuid
import random
from datetime import datetime, timedelta
from pathlib import Path


# Database configuration
DB_PATH = "Cloud_Infrastructure.db"


class AzureEnvironmentConfig:
    """Configuration for Azure cloud environments and services"""
    
    def __init__(self):
        # Environment configuration
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

        # Service configurations
        self.services = {
            "Microsoft.KeyVault": {
                "type": "vaults",
                "operations": ["VaultGet", "KeyGet", "KeyCreate", "SecretGet", "SecretSet"],
                "resultTypes": ["Success", "Failed"],
                "metrics": ["ServiceApiLatency", "SaturationShoebox", "Availability"],
                "diagnostic_categories": ["AuditEvent", "AzurePolicyEvaluation"]
            },
            "Microsoft.Sql": {
                "type": "servers/databases",
                "operations": ["DatabaseConnect", "QueryExecute", "BackupComplete", "DatabaseFailover"],
                "resultTypes": ["Succeeded", "Failed"],
                "metrics": ["cpu_percent", "storage_percent", "dtu_consumption_percent"],
                "diagnostic_categories": ["SQLSecurityAuditEvents", "AutomaticTuning"]
            },
            "Microsoft.Web": {
                "type": "sites",
                "operations": ["AppServicePlanUpdate", "WebAppRestart", "SiteConfigUpdate"],
                "resultTypes": ["Succeeded", "Failed", "InProgress"],
                "metrics": ["Http5xx", "ResponseTime", "CpuTime"],
                "diagnostic_categories": ["AppServiceHTTPLogs", "AppServiceConsoleLogs"]
            },
            "Microsoft.Storage": {
                "type": "storageAccounts",
                "operations": ["BlobGet", "BlobCreate", "ContainerDelete", "StorageRead"],
                "resultTypes": ["Success", "Failed"],
                "metrics": ["Availability", "Transactions", "SuccessE2ELatency"],
                "diagnostic_categories": ["StorageRead", "StorageWrite", "StorageDelete"]
            },
            "Microsoft.Compute": {
                "type": "virtualMachines",
                "operations": ["VMStart", "VMStop", "VMRestart", "VMDelete"],
                "resultTypes": ["Succeeded", "Failed"],
                "metrics": ["Percentage CPU", "Network In", "Network Out", "Disk Read Bytes"],
                "diagnostic_categories": ["VMDiagnostics", "VMPerformance"]
            },
            "Microsoft.Network": {
                "type": "applicationGateways",
                "operations": ["BackendHealthCheck", "RoutingRule", "SSLCertificateUpdate"],
                "resultTypes": ["Succeeded", "Failed"],
                "metrics": ["TotalRequests", "FailedRequests", "BackendResponseTime"],
                "diagnostic_categories": ["ApplicationGatewayAccessLog", "ApplicationGatewayPerformanceLog"]
            }
        }

        # Error patterns by environment and severity
        self.error_patterns = {
            "prod": {
                "critical": [
                    {
                        "message": "High Availability Failover Initiated",
                        "code": "PROD_CRITICAL_001",
                        "impact": "Service Downtime",
                        "mttr_minutes": random.randint(15, 45)
                    },
                    {
                        "message": "Database Deadlock Detected",
                        "code": "PROD_CRITICAL_002",
                        "impact": "Transaction Failure",
                        "mttr_minutes": random.randint(10, 30)
                    },
                    {
                        "message": "SSL Certificate Expiration Critical",
                        "code": "PROD_CRITICAL_003",
                        "impact": "Security Risk",
                        "mttr_minutes": random.randint(30, 60)
                    },
                    {
                        "message": "Memory Resource Exhaustion",
                        "code": "PROD_CRITICAL_004",
                        "impact": "System Crash",
                        "mttr_minutes": random.randint(20, 50)
                    }
                ],
                "high": [
                    {
                        "message": "Elevated Error Rate Detected",
                        "code": "PROD_HIGH_001",
                        "impact": "Performance Degradation",
                        "mttr_minutes": random.randint(30, 90)
                    },
                    {
                        "message": "Network Connectivity Issues",
                        "code": "PROD_HIGH_002",
                        "impact": "Intermittent Access",
                        "mttr_minutes": random.randint(45, 120)
                    },
                    {
                        "message": "Database Performance Degradation",
                        "code": "PROD_HIGH_003",
                        "impact": "Slow Queries",
                        "mttr_minutes": random.randint(60, 150)
                    }
                ],
                "medium": [
                    {
                        "message": "Cache Hit Rate Below Threshold",
                        "code": "PROD_MED_001",
                        "impact": "Minor Performance Impact",
                        "mttr_minutes": random.randint(120, 240)
                    },
                    {
                        "message": "API Rate Limit Warning",
                        "code": "PROD_MED_002",
                        "impact": "Potential Throttling",
                        "mttr_minutes": random.randint(90, 180)
                    }
                ],
                "low": [
                    {
                        "message": "Informational Log Anomaly",
                        "code": "PROD_LOW_001",
                        "impact": "None",
                        "mttr_minutes": random.randint(240, 480)
                    }
                ]
            },
            "uat": {
                "critical": [
                    {
                        "message": "Test Failover Simulation",
                        "code": "UAT_CRITICAL_001",
                        "impact": "Test Environment Down",
                        "mttr_minutes": random.randint(20, 60)
                    },
                    {
                        "message": "Load Test Resource Exhaustion",
                        "code": "UAT_CRITICAL_002",
                        "impact": "Test Failure",
                        "mttr_minutes": random.randint(15, 45)
                    }
                ],
                "high": [
                    {
                        "message": "Performance Test Threshold Breach",
                        "code": "UAT_HIGH_001",
                        "impact": "Test Metrics Failure",
                        "mttr_minutes": random.randint(60, 120)
                    },
                    {
                        "message": "API Integration Failure",
                        "code": "UAT_HIGH_002",
                        "impact": "Integration Test Blocked",
                        "mttr_minutes": random.randint(45, 90)
                    }
                ],
                "medium": [
                    {
                        "message": "Data Sync Issues",
                        "code": "UAT_MED_001",
                        "impact": "Test Data Inconsistency",
                        "mttr_minutes": random.randint(90, 180)
                    }
                ],
                "low": [
                    {
                        "message": "Test Configuration Warning",
                        "code": "UAT_LOW_001",
                        "impact": "None",
                        "mttr_minutes": random.randint(180, 360)
                    }
                ]
            },
            "dev": {
                "critical": [
                    {
                        "message": "Development Environment Down",
                        "code": "DEV_CRITICAL_001",
                        "impact": "Development Blocked",
                        "mttr_minutes": random.randint(30, 90)
                    },
                    {
                        "message": "Build Pipeline Failure",
                        "code": "DEV_CRITICAL_002",
                        "impact": "CI/CD Blocked",
                        "mttr_minutes": random.randint(20, 60)
                    }
                ],
                "high": [
                    {
                        "message": "Development API Gateway Issues",
                        "code": "DEV_HIGH_001",
                        "impact": "API Testing Blocked",
                        "mttr_minutes": random.randint(60, 120)
                    },
                    {
                        "message": "Local Development Stack Error",
                        "code": "DEV_HIGH_002",
                        "impact": "Development Delayed",
                        "mttr_minutes": random.randint(45, 90)
                    }
                ],
                "medium": [
                    {
                        "message": "Test Data Generation Failure",
                        "code": "DEV_MED_001",
                        "impact": "Testing Delayed",
                        "mttr_minutes": random.randint(120, 240)
                    }
                ],
                "low": [
                    {
                        "message": "Development Warning",
                        "code": "DEV_LOW_001",
                        "impact": "None",
                        "mttr_minutes": random.randint(240, 480)
                    }
                ]
            }
        }

    def get_resource_name(self, service, env):
        """Generate resource name based on service and environment"""
        prefix = self.environments[env]["resource_prefix"]
        service_short = service.split('.')[-1].lower()
        return f"{prefix}-{service_short}-{random.randint(1,999):03d}"

    def get_resource_id(self, service, env):
        """Generate Azure resource ID"""
        subscription_id = self.environments[env]["subscription_id"]
        region = random.choice(self.environments[env]["allowed_regions"])
        rg_name = f"{self.environments[env]['resource_prefix']}-rg-{region}"
        resource_name = self.get_resource_name(service, env)
        return f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/{service}/{self.services[service]['type']}/{resource_name}"


class IncidentLogGenerator:
    """Generator for Azure incident logs with different scenario types"""
    
    def __init__(self):
        self.config = AzureEnvironmentConfig()
        
    def generate_activity_log(self, env, scenario_type="normal"):
        """
        Generate activity log entry
        
        Args:
            env: Environment (prod, uat, dev)
            scenario_type: 'best', 'good', 'worst', 'normal'
        
        Returns:
            Dictionary containing activity log data
        """
        service = random.choice(list(self.config.services.keys()))
        operation = random.choice(self.config.services[service]["operations"])
        resource_id = self.config.get_resource_id(service, env)
        
        # Determine status and severity based on scenario type
        if scenario_type == "best":
            status = "Success" if "Success" in self.config.services[service]["resultTypes"] else "Succeeded"
            severity = None
            error_info = None
        elif scenario_type == "good":
            # 85% success, 15% low/medium issues
            if random.random() < 0.85:
                status = "Success" if "Success" in self.config.services[service]["resultTypes"] else "Succeeded"
                severity = None
                error_info = None
            else:
                status = "Failed"
                severity = random.choice(["low", "medium"])
                error_info = random.choice(self.config.error_patterns[env][severity])
        elif scenario_type == "worst":
            # 70% failures with high/critical issues
            if random.random() < 0.70:
                status = "Failed"
                severity = random.choice(["critical", "high"])
                error_info = random.choice(self.config.error_patterns[env][severity])
            else:
                status = "Success" if "Success" in self.config.services[service]["resultTypes"] else "Succeeded"
                severity = random.choice(["medium", "high"])
                error_info = random.choice(self.config.error_patterns[env][severity])
        else:  # normal
            # Random distribution
            if random.random() < 0.70:
                status = "Success" if "Success" in self.config.services[service]["resultTypes"] else "Succeeded"
                severity = None
                error_info = None
            else:
                status = "Failed"
                severity = random.choice(["critical", "high", "medium", "low"])
                error_info = random.choice(self.config.error_patterns[env][severity])
        
        log = {
            "correlationId": str(uuid.uuid4()),
            "eventTimestamp": (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat() + "Z",
            "category": "Administrative",
            "resourceId": resource_id,
            "operationName": {
                "value": operation,
                "localizedValue": operation
            },
            "status": {
                "value": status,
                "localizedValue": status
            },
            "subscriptionId": resource_id.split('/')[2],
            "tags": self.config.environments[env]["tags"],
            "properties": {
                "statusCode": 200 if status in ["Success", "Succeeded"] else random.choice([500, 503, 504, 429]),
                "serviceRequestId": str(uuid.uuid4()),
                "eventCategory": "Administrative",
                "environment": env.upper(),
                "resourceProvider": service,
                "scenarioType": scenario_type
            }
        }

        if error_info:
            log["properties"]["error"] = {
                "code": error_info["code"],
                "message": error_info["message"],
                "severity": severity.upper(),
                "impact": error_info["impact"],
                "estimatedMTTR": error_info["mttr_minutes"]
            }
            log["properties"]["alertTriggered"] = True
            log["properties"]["incidentId"] = f"INC-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

        return log

    def generate_metric_log(self, env, scenario_type="normal"):
        """
        Generate metric log entry
        
        Args:
            env: Environment (prod, uat, dev)
            scenario_type: 'best', 'good', 'worst', 'normal'
        
        Returns:
            Dictionary containing metric log data
        """
        service = random.choice(list(self.config.services.keys()))
        resource_id = self.config.get_resource_id(service, env)
        metric_name = random.choice(self.config.services[service]["metrics"])
        
        # Generate metric value based on scenario type
        if scenario_type == "best":
            # Optimal performance: 10-40% utilization
            value = random.uniform(10, 40)
            threshold_breach = False
        elif scenario_type == "good":
            # Good performance: 30-70% utilization, occasional spikes
            value = random.uniform(30, 70)
            threshold_breach = random.random() < 0.10  # 10% threshold breaches
        elif scenario_type == "worst":
            # Poor performance: 70-100% utilization, frequent breaches
            value = random.uniform(70, 100)
            threshold_breach = random.random() < 0.60  # 60% threshold breaches
        else:  # normal
            value = random.uniform(0, 100)
            threshold_breach = random.random() < 0.25  # 25% threshold breaches

        metric_log = {
            "time": datetime.now().isoformat() + "Z",
            "resourceId": resource_id,
            "metricName": metric_name,
            "timeGrain": "PT1M",
            "value": round(value, 2),
            "tags": self.config.environments[env]["tags"],
            "properties": {
                "environment": env.upper(),
                "subscription": self.config.environments[env]["subscription_name"],
                "metric_category": "Platform",
                "unit": "Percent" if "percent" in metric_name.lower() else "Count",
                "scenarioType": scenario_type,
                "thresholdBreach": threshold_breach
            }
        }

        if threshold_breach:
            metric_log["properties"]["alert"] = {
                "severity": "HIGH" if value > 85 else "MEDIUM" if value > 70 else "LOW",
                "threshold": 80 if scenario_type == "best" else 85,
                "message": f"{metric_name} exceeded threshold"
            }

        return metric_log


def create_tables(conn):
    """Create all required database tables"""
    cursor = conn.cursor()
    
    # Main incident_logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_logs (
            id TEXT PRIMARY KEY,
            incident_json TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL,
            environment TEXT,
            scenario_type TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Best case scenario table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_logs_best (
            id TEXT PRIMARY KEY,
            incident_json TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL,
            environment TEXT,
            scenario_type TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Good case scenario table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_logs_good (
            id TEXT PRIMARY KEY,
            incident_json TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL,
            environment TEXT,
            scenario_type TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Worst case scenario table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_logs_worst (
            id TEXT PRIMARY KEY,
            incident_json TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL,
            environment TEXT,
            scenario_type TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()


def generate_mock_data(total_records=1000):
    """
    Generate mock incident log data
    
    Args:
        total_records: Number of records to generate per scenario type
    """
    generator = IncidentLogGenerator()
    conn = sqlite3.connect(DB_PATH)
    
    # Create all tables
    create_tables(conn)
    cursor = conn.cursor()

    # Environment distribution (50% prod, 30% uat, 20% dev)
    env_distribution = {
        "prod": int(total_records * 0.5),
        "uat": int(total_records * 0.3),
        "dev": int(total_records * 0.2)
    }

    print("=" * 80)
    print("CLOUD INFRASTRUCTURE INCIDENT LOG GENERATOR")
    print("=" * 80)
    print(f"\nGenerating {total_records} total records per scenario type")
    print(f"Total records: {total_records * 3}")
    print(f"\nEnvironment distribution per scenario:")
    for env, count in env_distribution.items():
        print(f"  {env.upper()}: {count} records")

    # Clear existing data
    for table in ['incident_logs', 'incident_logs_best', 'incident_logs_good', 'incident_logs_worst']:
        cursor.execute(f"DELETE FROM {table}")

    # Storage for JSON export
    all_logs = []
    best_logs = []
    good_logs = []
    worst_logs = []

    records_created = {"all": 0, "best": 0, "good": 0, "worst": 0}
    
    print("\n" + "=" * 80)
    print("GENERATING DATASETS")
    print("=" * 80)
    
    # Generate data for each scenario type
    for scenario_type in ["best", "good", "worst"]:
        print(f"\n--- Generating {scenario_type.upper()} case scenario ---")
        
        for env, count in env_distribution.items():
            for i in range(count):
                # 70% activity logs, 30% metric logs
                if random.random() < 0.7:
                    log = generator.generate_activity_log(env, scenario_type)
                    source_type = "ActivityLog"
                else:
                    log = generator.generate_metric_log(env, scenario_type)
                    source_type = "MetricLog"

                # Extract metadata
                environment = log.get("properties", {}).get("environment", "UNKNOWN")
                severity = log.get("properties", {}).get("error", {}).get("severity", None)
                status = log.get("status", {}).get("value", "Unknown")
                
                record_id = str(uuid.uuid4())
                log_json = json.dumps(log)

                # Insert into all logs table
                cursor.execute("""
                    INSERT INTO incident_logs (id, incident_json, source_type, status, environment, scenario_type, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (record_id, log_json, source_type, status, environment, scenario_type, severity))
                
                all_logs.append({
                    "id": record_id,
                    "log": log,
                    "source_type": source_type,
                    "status": status,
                    "environment": environment,
                    "scenario_type": scenario_type,
                    "severity": severity
                })
                records_created["all"] += 1

                # Insert into scenario-specific table
                table_name = f"incident_logs_{scenario_type}"
                cursor.execute(f"""
                    INSERT INTO {table_name} (id, incident_json, source_type, status, environment, scenario_type, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (record_id, log_json, source_type, status, environment, scenario_type, severity))
                
                # Add to scenario-specific list
                if scenario_type == "best":
                    best_logs.append({
                        "id": record_id,
                        "log": log,
                        "source_type": source_type,
                        "status": status,
                        "environment": environment,
                        "scenario_type": scenario_type,
                        "severity": severity
                    })
                elif scenario_type == "good":
                    good_logs.append({
                        "id": record_id,
                        "log": log,
                        "source_type": source_type,
                        "status": status,
                        "environment": environment,
                        "scenario_type": scenario_type,
                        "severity": severity
                    })
                elif scenario_type == "worst":
                    worst_logs.append({
                        "id": record_id,
                        "log": log,
                        "source_type": source_type,
                        "status": status,
                        "environment": environment,
                        "scenario_type": scenario_type,
                        "severity": severity
                    })
                
                records_created[scenario_type] += 1

                if records_created["all"] % 200 == 0:
                    print(f"  Progress: {records_created['all']} total records created...")

    conn.commit()

    # Export to JSON files
    print("\n" + "=" * 80)
    print("EXPORTING TO JSON FILES")
    print("=" * 80)
    
    json_files = {
        "incident_logs_all.json": all_logs,
        "incident_logs_best.json": best_logs,
        "incident_logs_good.json": good_logs,
        "incident_logs_worst.json": worst_logs
    }
    
    for filename, data in json_files.items():
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Created: {filename} ({len(data)} records)")

    # Print detailed statistics
    print("\n" + "=" * 80)
    print("DATABASE STATISTICS")
    print("=" * 80)
    
    for table in ['incident_logs', 'incident_logs_best', 'incident_logs_good', 'incident_logs_worst']:
        print(f"\n--- {table.upper().replace('_', ' ')} ---")
        
        # Environment distribution
        cursor.execute(f"""
            SELECT environment, COUNT(*) as count
            FROM {table}
            GROUP BY environment
            ORDER BY count DESC
        """)
        print("  Environment Distribution:")
        for env, count in cursor.fetchall():
            print(f"    {env}: {count} records")
        
        # Source type distribution
        cursor.execute(f"""
            SELECT source_type, COUNT(*) as count
            FROM {table}
            GROUP BY source_type
        """)
        print("  Source Type Distribution:")
        for source, count in cursor.fetchall():
            print(f"    {source}: {count} records")
        
        # Severity distribution
        cursor.execute(f"""
            SELECT severity, COUNT(*) as count
            FROM {table}
            WHERE severity IS NOT NULL
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END
        """)
        print("  Severity Distribution:")
        severity_results = cursor.fetchall()
        if severity_results:
            for severity, count in severity_results:
                if severity:
                    print(f"    {severity}: {count} records")
        else:
            print("    No incidents (100% healthy)")
        
        # Status distribution
        cursor.execute(f"""
            SELECT status, COUNT(*) as count
            FROM {table}
            GROUP BY status
        """)
        print("  Status Distribution:")
        for status, count in cursor.fetchall():
            print(f"    {status}: {count} records")

    conn.close()
    
    print("\n" + "=" * 80)
    print("DATA GENERATION COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    print(f"\nGenerated Files:")
    print(f"  • Database: {DB_PATH}")
    print(f"  • JSON Files: 4 files (all, best, good, worst)")
    print(f"\nTotal Records: {records_created['all']}")
    print(f"  • Best Case: {records_created['best']}")
    print(f"  • Good Case: {records_created['good']}")
    print(f"  • Worst Case: {records_created['worst']}")


if __name__ == "__main__":
    # Generate 1000 records per scenario type (3000 total)
    generate_mock_data(1000)
