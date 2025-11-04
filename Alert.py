import sqlite3
import json
import uuid
import random
from datetime import datetime, timedelta
from pathlib import Path


# Database configuration
DB_PATH = "D:/incident_management/data/sqlite/incident_management.db"


class AzureEnvironmentConfig:
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
                },
                "email_recipients": {
                    "primary": "prod-ops@company.com",
                    "cc": ["sre-team@company.com", "management@company.com"]
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
                },
                "email_recipients": {
                    "primary": "uat-team@company.com",
                    "cc": ["qa-team@company.com"]
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
                },
                "email_recipients": {
                    "primary": "dev-team@company.com",
                    "cc": ["devops@company.com"]
                }
            }
        }

        # Azure services configuration
        self.services = {
            "Microsoft.Compute/virtualMachines": {
                "metrics": {
                    "Percentage CPU": {"threshold": 85, "unit": "Percent", "aggregation": "Average"},
                    "Available Memory Bytes": {"threshold": 500000000, "unit": "Bytes", "aggregation": "Average"},
                    "Disk Read Bytes": {"threshold": 100000000, "unit": "BytesPerSecond", "aggregation": "Total"}
                },
                "activities": ["VM Deallocated", "VM Started", "VM Stopped", "VM Deleted"]
            },
            "Microsoft.Sql/servers/databases": {
                "metrics": {
                    "cpu_percent": {"threshold": 90, "unit": "Percent", "aggregation": "Average"},
                    "storage_percent": {"threshold": 80, "unit": "Percent", "aggregation": "Maximum"},
                    "deadlock": {"threshold": 5, "unit": "Count", "aggregation": "Total"},
                    "connection_failed": {"threshold": 10, "unit": "Count", "aggregation": "Total"}
                },
                "activities": ["Database Deleted", "Firewall Rule Updated", "Database Scaled", "Backup Completed"]
            },
            "Microsoft.Web/sites": {
                "metrics": {
                    "Http5xx": {"threshold": 50, "unit": "Count", "aggregation": "Total"},
                    "ResponseTime": {"threshold": 5, "unit": "Seconds", "aggregation": "Average"},
                    "CpuTime": {"threshold": 120, "unit": "Seconds", "aggregation": "Total"},
                    "MemoryWorkingSet": {"threshold": 1000000000, "unit": "Bytes", "aggregation": "Average"}
                },
                "activities": ["App Service Restarted", "Configuration Updated", "SSL Certificate Updated", "Deployment Completed"]
            },
            "Microsoft.Storage/storageAccounts": {
                "metrics": {
                    "UsedCapacity": {"threshold": 900000000000, "unit": "Bytes", "aggregation": "Average"},
                    "Transactions": {"threshold": 100000, "unit": "Count", "aggregation": "Total"},
                    "SuccessE2ELatency": {"threshold": 1000, "unit": "Milliseconds", "aggregation": "Average"},
                    "Availability": {"threshold": 99, "unit": "Percent", "aggregation": "Average"}
                },
                "activities": ["Storage Account Updated", "Blob Container Deleted", "Storage Keys Regenerated", "Encryption Updated"]
            },
            "Microsoft.KeyVault/vaults": {
                "metrics": {
                    "ServiceApiLatency": {"threshold": 1000, "unit": "Milliseconds", "aggregation": "Average"},
                    "ServiceApiHit": {"threshold": 10000, "unit": "Count", "aggregation": "Total"},
                    "ServiceApiResult": {"threshold": 50, "unit": "Count", "aggregation": "Total"}
                },
                "activities": ["Secret Retrieved", "Key Created", "Certificate Expired", "Access Policy Updated"]
            }
        }

        # Severity-based alert patterns
        self.alert_templates = {
            "Sev0": {  # Critical
                "names": [
                    "Critical: Production Database Unavailable",
                    "Critical: Application Gateway Down",
                    "Critical: Memory Exhaustion Imminent",
                    "Critical: Storage Account Corruption Detected"
                ],
                "descriptions": [
                    "Service is completely unavailable. Immediate action required.",
                    "Critical system component failure detected. Business operations severely impacted.",
                    "Resource exhaustion will cause service failure within minutes.",
                    "Data integrity issue detected. Potential data loss risk."
                ],
                "actions": [
                    "1. Engage incident response team immediately
2. Check service health dashboard
3. Review recent deployments
4. Initiate failover procedures if available",
                    "1. Contact on-call engineer
2. Review application logs
3. Check dependency services
4. Prepare rollback plan",
                    "1. Scale up resources immediately
2. Identify memory leaks
3. Restart affected services
4. Monitor resource utilization",
                    "1. Isolate affected resources
2. Verify backup integrity
3. Contact support
4. Prepare incident report"
                ]
            },
            "Sev1": {  # High
                "names": [
                    "High: Elevated Error Rate Detected",
                    "High: Database Performance Degradation",
                    "High: SSL Certificate Expiring Soon",
                    "High: Unusual Network Traffic Pattern"
                ],
                "descriptions": [
                    "Error rate has exceeded acceptable threshold. Service quality impacted.",
                    "Query performance significantly degraded. User experience affected.",
                    "SSL certificate will expire within 7 days. Service interruption likely.",
                    "Anomalous traffic pattern detected. Possible security incident."
                ],
                "actions": [
                    "1. Review application logs for error patterns
2. Check recent code deployments
3. Monitor error trends
4. Notify development team",
                    "1. Run database performance diagnostics
2. Check for blocking queries
3. Review index usage
4. Consider scaling database tier",
                    "1. Renew SSL certificate immediately
2. Update certificate in Key Vault
3. Test certificate binding
4. Monitor for expiration warnings",
                    "1. Review network security logs
2. Check firewall rules
3. Investigate source IPs
4. Consider blocking suspicious traffic"
                ]
            },
            "Sev2": {  # Medium
                "names": [
                    "Medium: Resource Utilization High",
                    "Medium: Backup Job Failed",
                    "Medium: API Response Time Elevated",
                    "Medium: Unused Resources Detected"
                ],
                "descriptions": [
                    "Resource utilization approaching threshold. Performance may degrade.",
                    "Scheduled backup operation failed. Data protection at risk.",
                    "API latency higher than normal. User experience may be impacted.",
                    "Resources running without recent activity. Cost optimization needed."
                ],
                "actions": [
                    "1. Review resource utilization trends
2. Plan for capacity scaling
3. Optimize resource usage
4. Set up auto-scaling if needed",
                    "1. Check backup service status
2. Review backup logs
3. Retry backup operation
4. Verify storage availability",
                    "1. Review API performance metrics
2. Check backend service health
3. Analyze slow queries
4. Consider caching strategies",
                    "1. Review resource usage patterns
2. Identify idle resources
3. Deallocate or delete unused resources
4. Update cost reports"
                ]
            },
            "Sev3": {  # Low
                "names": [
                    "Low: Informational - Scheduled Maintenance",
                    "Low: Configuration Change Detected",
                    "Low: New Resource Created",
                    "Low: Diagnostic Setting Updated"
                ],
                "descriptions": [
                    "Informational alert about upcoming maintenance window.",
                    "Configuration change detected in monitored resource.",
                    "New Azure resource provisioned in subscription.",
                    "Diagnostic logging configuration has been modified."
                ],
                "actions": [
                    "1. Review maintenance schedule
2. Plan for service interruption
3. Notify stakeholders
4. Update change calendar",
                    "1. Review change details
2. Verify authorization
3. Update configuration documentation
4. Test affected services",
                    "1. Verify resource creation was authorized
2. Apply appropriate tags
3. Configure monitoring
4. Update CMDB",
                    "1. Review diagnostic changes
2. Verify log retention settings
3. Test log ingestion
4. Update documentation"
                ]
            }
        }


class AlertGenerator:
    def __init__(self):
        self.config = AzureEnvironmentConfig()
    
    def generate_resource_id(self, service, env):
        subscription_id = self.config.environments[env]["subscription_id"]
        region = random.choice(self.config.environments[env]["allowed_regions"])
        rg_name = f"{self.config.environments[env]['resource_prefix']}-rg-{region}"
        resource_name = f"{self.config.environments[env]['resource_prefix']}-{service.split('/')[-1]}-{random.randint(100, 999)}"
        return f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/{service}/{resource_name}"
    
    def generate_metric_alert(self, env, severity):
        service = random.choice(list(self.config.services.keys()))
        metric_name = random.choice(list(self.config.services[service]["metrics"].keys()))
        metric_config = self.config.services[service]["metrics"][metric_name]
        
        resource_id = self.generate_resource_id(service, env)
        alert_name = random.choice(self.config.alert_templates[severity]["names"])
        
        # Generate realistic metric value based on threshold
        threshold = metric_config["threshold"]
        if "cpu" in metric_name.lower() or "percent" in metric_name.lower():
            observed_value = threshold + random.uniform(5, 20)
        else:
            observed_value = threshold * random.uniform(1.1, 1.5)
        
        fired_time = datetime.utcnow() - timedelta(hours=random.randint(1, 720))
        
        alert_payload = {
            "schemaId": "AzureMonitorMetricAlert",
            "data": {
                "version": "2.0",
                "status": "Activated",
                "context": {
                    "timestamp": fired_time.isoformat() + "Z",
                    "id": f"{resource_id}/providers/Microsoft.Insights/metricAlerts/{alert_name}",
                    "name": alert_name,
                    "description": random.choice(self.config.alert_templates[severity]["descriptions"]),
                    "conditionType": "SingleResourceMultipleMetricCriteria",
                    "severity": severity,
                    "condition": {
                        "windowSize": "PT5M",
                        "allOf": [{
                            "metricName": metric_name,
                            "metricNamespace": service,
                            "operator": "GreaterThan",
                            "threshold": threshold,
                            "timeAggregation": metric_config["aggregation"],
                            "dimensions": [],
                            "metricValue": round(observed_value, 2),
                            "webTestName": None,
                            "metricUnit": metric_config["unit"]
                        }]
                    },
                    "subscriptionId": self.config.environments[env]["subscription_id"],
                    "resourceGroupName": resource_id.split('/')[4],
                    "resourceName": resource_id.split('/')[-1],
                    "resourceType": service,
                    "resourceId": resource_id,
                    "portalLink": f"https://portal.azure.com/#resource{resource_id}"
                }
            },
            "properties": {
                "environment": env.upper(),
                "tags": self.config.environments[env]["tags"]
            }
        }
        
        return {
            "alert_name": alert_name,
            "alert_type": "MetricAlert",
            "severity": severity,
            "environment": env.upper(),
            "fired_time": fired_time,
            "alert_payload": alert_payload,
            "resource_id": resource_id,
            "subscription_id": self.config.environments[env]["subscription_id"],
            "metric_name": metric_name,
            "threshold": threshold,
            "observed_value": round(observed_value, 2)
        }
    
    def generate_activity_alert(self, env, severity):
        service = random.choice(list(self.config.services.keys()))
        activity = random.choice(self.config.services[service]["activities"])
        
        resource_id = self.generate_resource_id(service, env)
        alert_name = random.choice(self.config.alert_templates[severity]["names"])
        
        fired_time = datetime.utcnow() - timedelta(hours=random.randint(1, 720))
        
        alert_payload = {
            "schemaId": "Microsoft.Insights/activityLogs",
            "data": {
                "status": "Activated",
                "context": {
                    "activityLog": {
                        "authorization": {
                            "action": f"{service}/write",
                            "scope": resource_id
                        },
                        "channels": "Operation",
                        "claims": json.dumps({
                            "aud": "https://management.azure.com/",
                            "iss": "https://sts.windows.net/tenant-id/",
                            "iat": int(fired_time.timestamp()),
                            "name": "admin@company.com"
                        }),
                        "caller": "admin@company.com",
                        "correlationId": str(uuid.uuid4()),
                        "eventSource": "Administrative",
                        "eventTimestamp": fired_time.isoformat() + "Z",
                        "eventDataId": str(uuid.uuid4()),
                        "level": "Critical" if severity == "Sev0" else "Warning",
                        "operationName": f"{service}/{activity}",
                        "operationId": str(uuid.uuid4()),
                        "properties": {
                            "eventCategory": "Administrative",
                            "entity": resource_id,
                            "message": random.choice(self.config.alert_templates[severity]["descriptions"]),
                            "hierarchy": self.config.environments[env]["subscription_id"]
                        },
                        "status": "Succeeded" if random.random() > 0.3 else "Failed",
                        "subStatus": "",
                        "subscriptionId": self.config.environments[env]["subscription_id"],
                        "resourceId": resource_id,
                        "resourceGroupName": resource_id.split('/')[4],
                        "resourceProviderName": service.split('/')[0],
                        "resourceType": service
                    }
                },
                "properties": {
                    "environment": env.upper(),
                    "tags": self.config.environments[env]["tags"]
                }
            }
        }
        
        return {
            "alert_name": alert_name,
            "alert_type": "ActivityLogAlert",
            "severity": severity,
            "environment": env.upper(),
            "fired_time": fired_time,
            "alert_payload": alert_payload,
            "resource_id": resource_id,
            "subscription_id": self.config.environments[env]["subscription_id"],
            "activity": activity
        }
    
    def generate_service_health_alert(self, env, severity):
        regions = self.config.environments[env]["allowed_regions"]
        affected_region = random.choice(regions)
        
        services = ["Virtual Machines", "SQL Database", "App Service", "Storage", "Key Vault"]
        affected_service = random.choice(services)
        
        fired_time = datetime.utcnow() - timedelta(hours=random.randint(1, 720))
        
        alert_name = f"Service Health: {affected_service} in {affected_region}"
        
        alert_payload = {
            "schemaId": "Microsoft.Insights/serviceHealth",
            "data": {
                "context": {
                    "eventSource": "ServiceHealth",
                    "eventTimestamp": fired_time.isoformat() + "Z",
                    "properties": {
                        "title": alert_name,
                        "service": affected_service,
                        "region": affected_region,
                        "communication": random.choice(self.config.alert_templates[severity]["descriptions"]),
                        "incidentType": random.choice(["Incident", "Maintenance", "Information", "ActionRequired"]),
                        "trackingId": str(uuid.uuid4()).upper(),
                        "impactStartTime": fired_time.isoformat() + "Z",
                        "impactMitigationTime": (fired_time + timedelta(hours=random.randint(1, 4))).isoformat() + "Z" if random.random() > 0.5 else "",
                        "impactedServices": json.dumps([{
                            "ServiceName": affected_service,
                            "ImpactedRegions": [{
                                "RegionName": affected_region
                            }]
                        }]),
                        "defaultLanguageTitle": alert_name,
                        "defaultLanguageContent": random.choice(self.config.alert_templates[severity]["descriptions"]),
                        "stage": random.choice(["Active", "Resolved", "Investigating"]),
                        "communicationId": str(uuid.uuid4()),
                        "version": "0.1.1"
                    }
                },
                "properties": {
                    "environment": env.upper(),
                    "subscriptionId": self.config.environments[env]["subscription_id"]
                }
            }
        }
        
        return {
            "alert_name": alert_name,
            "alert_type": "ServiceHealth",
            "severity": severity,
            "environment": env.upper(),
            "fired_time": fired_time,
            "alert_payload": alert_payload,
            "resource_id": f"/subscriptions/{self.config.environments[env]['subscription_id']}/providers/Microsoft.ServiceHealth",
            "subscription_id": self.config.environments[env]["subscription_id"],
            "affected_service": affected_service,
            "affected_region": affected_region
        }
    
    def generate_email_body(self, alert_data, env):
        recipients = self.config.environments[env]["email_recipients"]
        severity = alert_data["severity"]
        
        # Determine priority based on severity
        priority_map = {"Sev0": "Critical", "Sev1": "High", "Sev2": "Medium", "Sev3": "Low"}
        priority = priority_map[severity]
        
        # Get alert-specific details
        description = ""
        details = ""
        recommended_actions = random.choice(self.config.alert_templates[severity]["actions"])
        
        if alert_data["alert_type"] == "MetricAlert":
            description = f"Metric '{alert_data['metric_name']}' has exceeded threshold"
            details = f"""
            <tr><td><strong>Metric Name:</strong></td><td>{alert_data['metric_name']}</td></tr>
            <tr><td><strong>Threshold:</strong></td><td>{alert_data['threshold']}</td></tr>
            <tr><td><strong>Observed Value:</strong></td><td>{alert_data['observed_value']}</td></tr>
            """
        elif alert_data["alert_type"] == "ActivityLogAlert":
            description = f"Administrative activity detected: {alert_data['activity']}"
            details = f"""
            <tr><td><strong>Activity:</strong></td><td>{alert_data['activity']}</td></tr>
            <tr><td><strong>Operation:</strong></td><td>Administrative Action</td></tr>
            """
        else:
            description = f"Service health issue affecting {alert_data['affected_service']}"
            details = f"""
            <tr><td><strong>Affected Service:</strong></td><td>{alert_data['affected_service']}</td></tr>
            <tr><td><strong>Region:</strong></td><td>{alert_data['affected_region']}</td></tr>
            """
        
        # Generate HTML email body
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #d9534f; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
        .header.sev1 {{ background: #f0ad4e; }}
        .header.sev2 {{ background: #5bc0de; }}
        .header.sev3 {{ background: #5cb85c; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #ddd; }}
        .footer {{ background: #333; color: white; padding: 15px; text-align: center; border-radius: 0 0 5px 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
        .actions {{ background: #fff3cd; padding: 15px; margin: 15px 0; border-left: 4px solid #ffc107; }}
        .severity-badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header {'sev' + severity[-1].lower()}">
            <h2>🚨 Azure Monitor Alert</h2>
            <p><strong>{alert_data['alert_name']}</strong></p>
        </div>
        <div class="content">
            <p><span class="severity-badge" style="background-color: {'#d9534f' if severity=='Sev0' else '#f0ad4e' if severity=='Sev1' else '#5bc0de' if severity=='Sev2' else '#5cb85c'}; color: white;">Severity: {severity}</span></p>
            
            <h3>Alert Summary</h3>
            <p>{description}</p>
            
            <h3>Details</h3>
            <table>
                <tr><td><strong>Environment:</strong></td><td>{env.upper()}</td></tr>
                <tr><td><strong>Alert Type:</strong></td><td>{alert_data['alert_type']}</td></tr>
                <tr><td><strong>Fired Time:</strong></td><td>{alert_data['fired_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
                {details}
                <tr><td><strong>Resource:</strong></td><td>{alert_data['resource_id']}</td></tr>
                <tr><td><strong>Subscription:</strong></td><td>{alert_data['subscription_id']}</td></tr>
            </table>
            
            <div class="actions">
                <h3>📋 Recommended Actions</h3>
                <pre>{recommended_actions}</pre>
            </div>
            
            <p><strong>Portal Link:</strong> <a href="https://portal.azure.com">View in Azure Portal</a></p>
        </div>
        <div class="footer">
            <p>This is an automated alert from Azure Monitor</p>
            <p>Environment: {env.upper()} | Subscription: {self.config.environments[env]['subscription_name']}</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Plain text version
        plain_text = f"""
Azure Monitor Alert: {alert_data['alert_name']}

Severity: {severity}
Environment: {env.upper()}
Alert Type: {alert_data['alert_type']}
Fired Time: {alert_data['fired_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}

{description}

Resource: {alert_data['resource_id']}
Subscription: {alert_data['subscription_id']}

Recommended Actions:
{recommended_actions}

View in Azure Portal: https://portal.azure.com
        """
        
        email_body = {
            "subject": f"[{severity}] Azure Monitor Alert: {alert_data['alert_name']}",
            "recipient": recipients["primary"],
            "cc": recipients["cc"],
            "priority": priority,
            "html_body": html_body.strip(),
            "plain_text_body": plain_text.strip(),
            "sent_time": alert_data['fired_time'].isoformat() + "Z",
            "alert_id": alert_data.get("alert_id", str(uuid.uuid4())),
            "environment": env.upper()
        }
        
        return email_body


def create_alerts_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS azure_alerts (
        alert_id TEXT PRIMARY KEY,
        alert_name TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        environment TEXT NOT NULL,
        alert_status TEXT NOT NULL,
        fired_time TEXT NOT NULL,
        resolved_time TEXT,
        alert_payload TEXT NOT NULL,
        email_body TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        subscription_id TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    conn.commit()
    conn.close()
    print("Created azure_alerts table...")


def generate_alerts(total_records=1000):
    generator = AlertGenerator()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Environment distribution
    env_distribution = {
        "prod": int(total_records * 0.5),
        "uat": int(total_records * 0.3),
        "dev": int(total_records * 0.2)
    }
    
    # Alert type distribution
    alert_type_weights = {
        "metric": 0.5,
        "activity": 0.3,
        "service_health": 0.2
    }
    
    # Severity distribution (environment-specific)
    severity_distribution = {
        "prod": {"Sev0": 0.2, "Sev1": 0.3, "Sev2": 0.3, "Sev3": 0.2},
        "uat": {"Sev0": 0.1, "Sev1": 0.2, "Sev2": 0.4, "Sev3": 0.3},
        "dev": {"Sev0": 0.05, "Sev1": 0.15, "Sev2": 0.4, "Sev3": 0.4}
    }
    
    print("Generating alerts with environment distribution:")
    for env, count in env_distribution.items():
        print(f"{env.upper()}: {count} records")
    
    # Clear existing data
    cursor.execute("DELETE FROM azure_alerts")
    
    records_created = 0
    resolved_count = 0
    
    for env, count in env_distribution.items():
        for i in range(count):
            # Determine severity based on environment
            severity = random.choices(
                list(severity_distribution[env].keys()),
                weights=list(severity_distribution[env].values())
            )[0]
            
            # Determine alert type
            alert_type_choice = random.choices(
                ["metric", "activity", "service_health"],
                weights=[alert_type_weights["metric"], alert_type_weights["activity"], alert_type_weights["service_health"]]
            )[0]
            
            # Generate alert based on type
            if alert_type_choice == "metric":
                alert_data = generator.generate_metric_alert(env, severity)
            elif alert_type_choice == "activity":
                alert_data = generator.generate_activity_alert(env, severity)
            else:
                alert_data = generator.generate_service_health_alert(env, severity)
            
            # Generate alert ID
            alert_id = str(uuid.uuid4())
            alert_data["alert_id"] = alert_id
            
            # Determine if alert is resolved (60% resolved)
            is_resolved = random.random() < 0.6
            alert_status = "Resolved" if is_resolved else random.choice(["Fired", "Acknowledged"])
            
            # Generate resolved time if applicable
            resolved_time = None
            if is_resolved:
                resolution_hours = random.randint(1, 48)
                resolved_time = (alert_data["fired_time"] + timedelta(hours=resolution_hours)).isoformat() + "Z"
                resolved_count += 1
            
            # Generate email body
            email_body = generator.generate_email_body(alert_data, env)
            
            # Insert into database
            cursor.execute("""
                INSERT INTO azure_alerts (
                    alert_id, alert_name, alert_type, severity, environment,
                    alert_status, fired_time, resolved_time, alert_payload,
                    email_body, resource_id, subscription_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id,
                alert_data["alert_name"],
                alert_data["alert_type"],
                alert_data["severity"],
                alert_data["environment"],
                alert_status,
                alert_data["fired_time"].isoformat() + "Z",
                resolved_time,
                json.dumps(alert_data["alert_payload"]),
                json.dumps(email_body),
                alert_data["resource_id"],
                alert_data["subscription_id"]
            ))
            
            records_created += 1
            if records_created % 100 == 0:
                print(f"Created {records_created} records...")
    
    conn.commit()
    
    # Print summary statistics
    print("
Final Distribution:")
    cursor.execute("""
        SELECT 
            environment,
            alert_type,
            COUNT(*) as count
        FROM azure_alerts
        GROUP BY environment, alert_type
        ORDER BY environment, alert_type
    """)
    
    results = cursor.fetchall()
    for env, alert_type, count in results:
        print(f"Environment: {env}, Type: {alert_type}, Count: {count}")
    
    print(f"
Alert generation completed!")
    print(f"Total alerts: {records_created}")
    print(f"Resolved: {resolved_count}")
    print(f"Active: {records_created - resolved_count}")
    
    conn.close()


if __name__ == "__main__":
    create_alerts_table()
    generate_alerts(1000)
