"""
Azure Alert Message Generator
AI Agent for Cloud Infrastructure Incident Management

This script generates realistic Azure alert messages with three scenario types:
BEST, GOOD, and WORST cases.

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
            },
            "Microsoft.Network/applicationGateways": {
                "metrics": {
                    "TotalRequests": {"threshold": 50000, "unit": "Count", "aggregation": "Total"},
                    "FailedRequests": {"threshold": 100, "unit": "Count", "aggregation": "Total"},
                    "BackendResponseTime": {"threshold": 2000, "unit": "Milliseconds", "aggregation": "Average"}
                },
                "activities": ["Backend Pool Updated", "SSL Certificate Renewed", "WAF Policy Applied", "Health Probe Failed"]
            }
        }

        # Severity-based alert patterns
        self.alert_templates = {
            "Sev0": {  # Critical
                "names": [
                    "Critical: Production Database Unavailable",
                    "Critical: Application Gateway Down",
                    "Critical: Memory Exhaustion Imminent",
                    "Critical: Storage Account Corruption Detected",
                    "Critical: Complete Service Outage",
                    "Critical: Data Center Connectivity Lost"
                ],
                "descriptions": [
                    "Service is completely unavailable. Immediate action required.",
                    "Critical system component failure detected. Business operations severely impacted.",
                    "Resource exhaustion will cause service failure within minutes.",
                    "Data integrity issue detected. Potential data loss risk.",
                    "Multiple services down across production environment.",
                    "Network connectivity failure affecting all resources in region."
                ],
                "actions": [
                    "1. Engage incident response team immediately\n2. Check service health dashboard\n3. Review recent deployments\n4. Initiate failover procedures if available",
                    "1. Contact on-call engineer\n2. Review application logs\n3. Check dependency services\n4. Prepare rollback plan",
                    "1. Scale up resources immediately\n2. Identify memory leaks\n3. Restart affected services\n4. Monitor resource utilization",
                    "1. Isolate affected resources\n2. Verify backup integrity\n3. Contact support\n4. Prepare incident report"
                ],
                "mttr_minutes": (15, 60)
            },
            "Sev1": {  # High
                "names": [
                    "High: Elevated Error Rate Detected",
                    "High: Database Performance Degradation",
                    "High: SSL Certificate Expiring Soon",
                    "High: Unusual Network Traffic Pattern",
                    "High: API Gateway Throttling",
                    "High: Backup Job Consecutive Failures"
                ],
                "descriptions": [
                    "Error rate has exceeded acceptable threshold. Service quality impacted.",
                    "Query performance significantly degraded. User experience affected.",
                    "SSL certificate will expire within 7 days. Service interruption likely.",
                    "Anomalous traffic pattern detected. Possible security incident.",
                    "API request rate exceeding limits. Service degradation imminent.",
                    "Multiple backup operations failed. Data protection at risk."
                ],
                "actions": [
                    "1. Review application logs for error patterns\n2. Check recent code deployments\n3. Monitor error trends\n4. Notify development team",
                    "1. Run database performance diagnostics\n2. Check for blocking queries\n3. Review index usage\n4. Consider scaling database tier",
                    "1. Renew SSL certificate immediately\n2. Update certificate in Key Vault\n3. Test certificate binding\n4. Monitor for expiration warnings",
                    "1. Review network security logs\n2. Check firewall rules\n3. Investigate source IPs\n4. Consider blocking suspicious traffic"
                ],
                "mttr_minutes": (60, 240)
            },
            "Sev2": {  # Medium
                "names": [
                    "Medium: Resource Utilization High",
                    "Medium: Backup Job Failed",
                    "Medium: API Response Time Elevated",
                    "Medium: Unused Resources Detected",
                    "Medium: Configuration Drift Detected",
                    "Medium: Cost Anomaly Detected"
                ],
                "descriptions": [
                    "Resource utilization approaching threshold. Performance may degrade.",
                    "Scheduled backup operation failed. Data protection at risk.",
                    "API latency higher than normal. User experience may be impacted.",
                    "Resources running without recent activity. Cost optimization needed.",
                    "Resource configuration differs from approved baseline.",
                    "Spending pattern shows unusual increase compared to baseline."
                ],
                "actions": [
                    "1. Review resource utilization trends\n2. Plan for capacity scaling\n3. Optimize resource usage\n4. Set up auto-scaling if needed",
                    "1. Check backup service status\n2. Review backup logs\n3. Retry backup operation\n4. Verify storage availability",
                    "1. Review API performance metrics\n2. Check backend service health\n3. Analyze slow queries\n4. Consider caching strategies",
                    "1. Review resource usage patterns\n2. Identify idle resources\n3. Deallocate or delete unused resources\n4. Update cost reports"
                ],
                "mttr_minutes": (240, 480)
            },
            "Sev3": {  # Low
                "names": [
                    "Low: Informational - Scheduled Maintenance",
                    "Low: Configuration Change Detected",
                    "Low: New Resource Created",
                    "Low: Diagnostic Setting Updated",
                    "Low: Tag Compliance Warning",
                    "Low: License Expiration Notice"
                ],
                "descriptions": [
                    "Informational alert about upcoming maintenance window.",
                    "Configuration change detected in monitored resource.",
                    "New Azure resource provisioned in subscription.",
                    "Diagnostic logging configuration has been modified.",
                    "Resource missing required tags per policy.",
                    "Software license approaching expiration date."
                ],
                "actions": [
                    "1. Review maintenance schedule\n2. Plan for service interruption\n3. Notify stakeholders\n4. Update change calendar",
                    "1. Review change details\n2. Verify authorization\n3. Update configuration documentation\n4. Test affected services",
                    "1. Verify resource creation was authorized\n2. Apply appropriate tags\n3. Configure monitoring\n4. Update CMDB",
                    "1. Review diagnostic changes\n2. Verify log retention settings\n3. Test log ingestion\n4. Update documentation"
                ],
                "mttr_minutes": (480, 1440)
            }
        }


class AlertGenerator:
    """Generator for Azure alert messages with different scenario types"""
    
    def __init__(self):
        self.config = AzureEnvironmentConfig()
    
    def generate_resource_id(self, service, env):
        """Generate Azure resource ID"""
        subscription_id = self.config.environments[env]["subscription_id"]
        region = random.choice(self.config.environments[env]["allowed_regions"])
        rg_name = f"{self.config.environments[env]['resource_prefix']}-rg-{region}"
        resource_name = f"{self.config.environments[env]['resource_prefix']}-{service.split('/')[-1]}-{random.randint(100, 999)}"
        return f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/{service}/{resource_name}"
    
    def determine_severity_for_scenario(self, scenario_type, env):
        """
        Determine severity distribution based on scenario type
        
        Args:
            scenario_type: 'best', 'good', 'worst'
            env: Environment name
        
        Returns:
            Severity level (Sev0, Sev1, Sev2, Sev3)
        """
        if scenario_type == "best":
            # Best case: Only Sev3 (informational) alerts
            return "Sev3"
        elif scenario_type == "good":
            # Good case: Mostly Sev2 and Sev3, rare Sev1
            weights = [0, 0.1, 0.4, 0.5]  # Sev0, Sev1, Sev2, Sev3
        elif scenario_type == "worst":
            # Worst case: High proportion of Sev0 and Sev1
            if env == "prod":
                weights = [0.4, 0.4, 0.15, 0.05]  # Sev0, Sev1, Sev2, Sev3
            elif env == "uat":
                weights = [0.3, 0.4, 0.2, 0.1]
            else:  # dev
                weights = [0.2, 0.3, 0.3, 0.2]
        else:  # normal
            # Normal distribution
            if env == "prod":
                weights = [0.2, 0.3, 0.3, 0.2]
            elif env == "uat":
                weights = [0.1, 0.2, 0.4, 0.3]
            else:  # dev
                weights = [0.05, 0.15, 0.4, 0.4]
        
        severities = ["Sev0", "Sev1", "Sev2", "Sev3"]
        return random.choices(severities, weights=weights)[0]
    
    def generate_metric_alert(self, env, severity, scenario_type="normal"):
        """Generate metric-based alert"""
        service = random.choice(list(self.config.services.keys()))
        metric_name = random.choice(list(self.config.services[service]["metrics"].keys()))
        metric_config = self.config.services[service]["metrics"][metric_name]
        
        resource_id = self.generate_resource_id(service, env)
        alert_name = random.choice(self.config.alert_templates[severity]["names"])
        
        # Generate realistic metric value based on threshold and scenario
        threshold = metric_config["threshold"]
        if scenario_type == "best":
            # Below threshold, healthy
            observed_value = threshold * random.uniform(0.5, 0.8)
        elif scenario_type == "good":
            # Slightly above threshold occasionally
            observed_value = threshold * random.uniform(0.95, 1.15)
        elif scenario_type == "worst":
            # Significantly above threshold
            observed_value = threshold * random.uniform(1.3, 2.0)
        else:  # normal
            observed_value = threshold * random.uniform(1.1, 1.5)
        
        fired_time = datetime.now() - timedelta(hours=random.randint(1, 720))
        
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
                "tags": self.config.environments[env]["tags"],
                "scenarioType": scenario_type
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
            "observed_value": round(observed_value, 2),
            "scenario_type": scenario_type
        }
    
    def generate_activity_alert(self, env, severity, scenario_type="normal"):
        """Generate activity log alert"""
        service = random.choice(list(self.config.services.keys()))
        activity = random.choice(self.config.services[service]["activities"])
        
        resource_id = self.generate_resource_id(service, env)
        alert_name = random.choice(self.config.alert_templates[severity]["names"])
        
        fired_time = datetime.now() - timedelta(hours=random.randint(1, 720))
        
        # Activity status based on scenario
        if scenario_type == "best":
            status = "Succeeded"
        elif scenario_type == "worst":
            status = "Failed" if random.random() < 0.6 else "Succeeded"
        else:
            status = "Failed" if random.random() < 0.3 else "Succeeded"
        
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
                        "level": "Critical" if severity == "Sev0" else "Warning" if severity == "Sev1" else "Informational",
                        "operationName": f"{service}/{activity}",
                        "operationId": str(uuid.uuid4()),
                        "properties": {
                            "eventCategory": "Administrative",
                            "entity": resource_id,
                            "message": random.choice(self.config.alert_templates[severity]["descriptions"]),
                            "hierarchy": self.config.environments[env]["subscription_id"]
                        },
                        "status": status,
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
                    "tags": self.config.environments[env]["tags"],
                    "scenarioType": scenario_type
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
            "activity": activity,
            "activity_status": status,
            "scenario_type": scenario_type
        }
    
    def generate_service_health_alert(self, env, severity, scenario_type="normal"):
        """Generate service health alert"""
        regions = self.config.environments[env]["allowed_regions"]
        affected_region = random.choice(regions)
        
        services = ["Virtual Machines", "SQL Database", "App Service", "Storage", "Key Vault", "Application Gateway"]
        affected_service = random.choice(services)
        
        fired_time = datetime.now() - timedelta(hours=random.randint(1, 720))
        
        alert_name = f"Service Health: {affected_service} in {affected_region}"
        
        # Incident type based on scenario
        if scenario_type == "best":
            incident_type = "Information"
            stage = "Resolved"
        elif scenario_type == "worst":
            incident_type = random.choice(["Incident", "ActionRequired"])
            stage = random.choice(["Active", "Investigating"])
        else:
            incident_type = random.choice(["Incident", "Maintenance", "Information"])
            stage = random.choice(["Active", "Resolved", "Investigating"])
        
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
                        "incidentType": incident_type,
                        "trackingId": str(uuid.uuid4()).upper(),
                        "impactStartTime": fired_time.isoformat() + "Z",
                        "impactMitigationTime": (fired_time + timedelta(hours=random.randint(1, 4))).isoformat() + "Z" if stage == "Resolved" else "",
                        "impactedServices": json.dumps([{
                            "ServiceName": affected_service,
                            "ImpactedRegions": [{
                                "RegionName": affected_region
                            }]
                        }]),
                        "defaultLanguageTitle": alert_name,
                        "defaultLanguageContent": random.choice(self.config.alert_templates[severity]["descriptions"]),
                        "stage": stage,
                        "communicationId": str(uuid.uuid4()),
                        "version": "0.1.1"
                    }
                },
                "properties": {
                    "environment": env.upper(),
                    "subscriptionId": self.config.environments[env]["subscription_id"],
                    "scenarioType": scenario_type
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
            "affected_region": affected_region,
            "incident_type": incident_type,
            "stage": stage,
            "scenario_type": scenario_type
        }
    
    def generate_email_body(self, alert_data, env):
        """Generate email notification body"""
        recipients = self.config.environments[env]["email_recipients"]
        severity = alert_data["severity"]
        
        # Determine priority based on severity
        priority_map = {"Sev0": "Critical", "Sev1": "High", "Sev2": "Medium", "Sev3": "Low"}
        priority = priority_map[severity]
        
        # Get MTTR estimate
        mttr_range = self.config.alert_templates[severity]["mttr_minutes"]
        estimated_mttr = random.randint(mttr_range[0], mttr_range[1])
        
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
            <tr><td><strong>Deviation:</strong></td><td>{round((alert_data['observed_value'] / alert_data['threshold'] - 1) * 100, 2)}%</td></tr>
            """
        elif alert_data["alert_type"] == "ActivityLogAlert":
            description = f"Administrative activity detected: {alert_data['activity']}"
            details = f"""
            <tr><td><strong>Activity:</strong></td><td>{alert_data['activity']}</td></tr>
            <tr><td><strong>Operation:</strong></td><td>Administrative Action</td></tr>
            <tr><td><strong>Status:</strong></td><td>{alert_data['activity_status']}</td></tr>
            """
        else:
            description = f"Service health issue affecting {alert_data['affected_service']}"
            details = f"""
            <tr><td><strong>Affected Service:</strong></td><td>{alert_data['affected_service']}</td></tr>
            <tr><td><strong>Region:</strong></td><td>{alert_data['affected_region']}</td></tr>
            <tr><td><strong>Incident Type:</strong></td><td>{alert_data['incident_type']}</td></tr>
            <tr><td><strong>Stage:</strong></td><td>{alert_data['stage']}</td></tr>
            """
        
        # Generate HTML email body
        severity_colors = {
            "Sev0": "#d9534f",
            "Sev1": "#f0ad4e",
            "Sev2": "#5bc0de",
            "Sev3": "#5cb85c"
        }
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }}
        .container {{ max-width: 700px; margin: 0 auto; padding: 20px; background-color: #f4f4f4; }}
        .header {{ background: {severity_colors[severity]}; color: white; padding: 25px; border-radius: 8px 8px 0 0; }}
        .header h2 {{ margin: 0 0 10px 0; font-size: 24px; }}
        .content {{ background: white; padding: 30px; border: 1px solid #ddd; border-top: none; }}
        .footer {{ background: #2c3e50; color: white; padding: 20px; text-align: center; border-radius: 0 0 8px 8px; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        td {{ padding: 12px 8px; border-bottom: 1px solid #eee; }}
        td:first-child {{ width: 40%; font-weight: 600; color: #555; }}
        .actions {{ background: #fff3cd; padding: 20px; margin: 20px 0; border-left: 5px solid #ffc107; border-radius: 4px; }}
        .actions h3 {{ margin-top: 0; color: #856404; }}
        .actions pre {{ background: white; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; font-family: 'Courier New', monospace; font-size: 13px; }}
        .severity-badge {{ display: inline-block; padding: 8px 15px; border-radius: 20px; font-weight: bold; font-size: 14px; }}
        .metric-card {{ background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid {severity_colors[severity]}; }}
        .btn {{ display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 10px 5px; }}
        .btn:hover {{ background: #0056b3; }}
        .timeline {{ margin: 20px 0; }}
        .timeline-item {{ padding: 10px 0; border-left: 2px solid #ddd; padding-left: 20px; margin-left: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🚨 Azure Monitor Alert</h2>
            <p style="margin: 5px 0; font-size: 18px;"><strong>{alert_data['alert_name']}</strong></p>
            <p style="margin: 5px 0; font-size: 14px;">Scenario: {alert_data['scenario_type'].upper()}</p>
        </div>
        <div class="content">
            <p>
                <span class="severity-badge" style="background-color: {severity_colors[severity]}; color: white;">
                    {severity} - {priority} Priority
                </span>
            </p>
            
            <h3 style="color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px;">📊 Alert Summary</h3>
            <p style="font-size: 15px; line-height: 1.8;">{description}</p>
            
            <div class="metric-card">
                <strong>Estimated Resolution Time:</strong> {estimated_mttr} minutes<br>
                <strong>Business Impact:</strong> {self.config.environments[env]['tags']['BusinessCriticality']}
            </div>
            
            <h3 style="color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px;">📋 Alert Details</h3>
            <table>
                <tr><td><strong>Environment:</strong></td><td>{env.upper()}</td></tr>
                <tr><td><strong>Alert Type:</strong></td><td>{alert_data['alert_type']}</td></tr>
                <tr><td><strong>Fired Time:</strong></td><td>{alert_data['fired_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
                <tr><td><strong>Scenario Type:</strong></td><td>{alert_data['scenario_type'].upper()}</td></tr>
                {details}
                <tr><td><strong>Resource:</strong></td><td style="word-break: break-all; font-size: 12px;">{alert_data['resource_id']}</td></tr>
                <tr><td><strong>Subscription:</strong></td><td>{alert_data['subscription_id']}</td></tr>
                <tr><td><strong>Cost Center:</strong></td><td>{self.config.environments[env]['tags']['CostCenter']}</td></tr>
            </table>
            
            <div class="actions">
                <h3>🔧 Recommended Actions</h3>
                <pre>{recommended_actions}</pre>
            </div>
            
            <div class="timeline">
                <h3 style="color: #2c3e50;">⏱️ Response Timeline</h3>
                <div class="timeline-item">
                    <strong>Immediate (0-15 min):</strong> Acknowledge alert and assess impact
                </div>
                <div class="timeline-item">
                    <strong>Short-term (15-60 min):</strong> Implement temporary mitigation
                </div>
                <div class="timeline-item">
                    <strong>Resolution ({estimated_mttr} min):</strong> Complete permanent fix and verification
                </div>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="https://portal.azure.com/#resource{alert_data['resource_id']}" class="btn">View in Azure Portal</a>
                <a href="https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alerts" class="btn" style="background: #28a745;">View All Alerts</a>
            </div>
        </div>
        <div class="footer">
            <p style="margin: 5px 0;"><strong>This is an automated alert from Azure Monitor</strong></p>
            <p style="margin: 5px 0;">Environment: {env.upper()} | Subscription: {self.config.environments[env]['subscription_name']}</p>
            <p style="margin: 5px 0;">Alert ID: {alert_data.get('alert_id', 'N/A')}</p>
            <p style="margin: 15px 0 5px 0; font-size: 11px; color: #95a5a6;">
                This message was sent to {recipients['primary']} and CC'd to {', '.join(recipients['cc'])}
            </p>
        </div>
    </div>
</body>
</html>
        """
        
        # Plain text version
        plain_text = f"""
Azure Monitor Alert: {alert_data['alert_name']}

Severity: {severity} ({priority} Priority)
Environment: {env.upper()}
Alert Type: {alert_data['alert_type']}
Fired Time: {alert_data['fired_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}
Scenario: {alert_data['scenario_type'].upper()}

{description}

Estimated Resolution Time: {estimated_mttr} minutes
Business Impact: {self.config.environments[env]['tags']['BusinessCriticality']}

Resource: {alert_data['resource_id']}
Subscription: {alert_data['subscription_id']}

Recommended Actions:
{recommended_actions}

View in Azure Portal: https://portal.azure.com/#resource{alert_data['resource_id']}
        """
        
        email_body = {
            "subject": f"[{severity}] [{env.upper()}] {alert_data['alert_name']}",
            "recipient": recipients["primary"],
            "cc": recipients["cc"],
            "priority": priority,
            "html_body": html_body.strip(),
            "plain_text_body": plain_text.strip(),
            "sent_time": alert_data['fired_time'].isoformat() + "Z",
            "alert_id": alert_data.get("alert_id", str(uuid.uuid4())),
            "environment": env.upper(),
            "estimated_mttr": estimated_mttr,
            "scenario_type": alert_data['scenario_type']
        }
        
        return email_body


def create_tables(conn):
    """Create all required database tables"""
    cursor = conn.cursor()
    
    # Main azure_alerts table
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
            scenario_type TEXT NOT NULL,
            estimated_mttr INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Best case scenario table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS azure_alerts_best (
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
            scenario_type TEXT NOT NULL,
            estimated_mttr INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Good case scenario table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS azure_alerts_good (
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
            scenario_type TEXT NOT NULL,
            estimated_mttr INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Worst case scenario table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS azure_alerts_worst (
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
            scenario_type TEXT NOT NULL,
            estimated_mttr INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()


def generate_alerts(total_records=1000):
    """
    Generate mock alert data
    
    Args:
        total_records: Number of records to generate per scenario type
    """
    generator = AlertGenerator()
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
    
    # Alert type distribution
    alert_type_weights = {
        "metric": 0.5,
        "activity": 0.3,
        "service_health": 0.2
    }
    
    print("=" * 80)
    print("AZURE ALERT MESSAGE GENERATOR")
    print("=" * 80)
    print(f"\nGenerating {total_records} total records per scenario type")
    print(f"Total records: {total_records * 3}")
    print(f"\nEnvironment distribution per scenario:")
    for env, count in env_distribution.items():
        print(f"  {env.upper()}: {count} records")
    
    # Clear existing data
    for table in ['azure_alerts', 'azure_alerts_best', 'azure_alerts_good', 'azure_alerts_worst']:
        cursor.execute(f"DELETE FROM {table}")
    
    # Storage for JSON export
    all_alerts = []
    best_alerts = []
    good_alerts = []
    worst_alerts = []
    
    records_created = {"all": 0, "best": 0, "good": 0, "worst": 0}
    
    print("\n" + "=" * 80)
    print("GENERATING DATASETS")
    print("=" * 80)
    
    # Generate data for each scenario type
    for scenario_type in ["best", "good", "worst"]:
        print(f"\n--- Generating {scenario_type.upper()} case scenario ---")
        
        for env, count in env_distribution.items():
            for i in range(count):
                # Determine severity based on scenario type
                severity = generator.determine_severity_for_scenario(scenario_type, env)
                
                # Determine alert type
                alert_type_choice = random.choices(
                    ["metric", "activity", "service_health"],
                    weights=[alert_type_weights["metric"], alert_type_weights["activity"], alert_type_weights["service_health"]]
                )[0]
                
                # Generate alert based on type
                if alert_type_choice == "metric":
                    alert_data = generator.generate_metric_alert(env, severity, scenario_type)
                elif alert_type_choice == "activity":
                    alert_data = generator.generate_activity_alert(env, severity, scenario_type)
                else:
                    alert_data = generator.generate_service_health_alert(env, severity, scenario_type)
                
                # Generate alert ID
                alert_id = str(uuid.uuid4())
                alert_data["alert_id"] = alert_id
                
                # Determine if alert is resolved (based on scenario)
                if scenario_type == "best":
                    is_resolved = True
                    resolution_hours = random.uniform(0.5, 2)
                elif scenario_type == "good":
                    is_resolved = random.random() < 0.75  # 75% resolved
                    resolution_hours = random.randint(1, 24)
                elif scenario_type == "worst":
                    is_resolved = random.random() < 0.30  # 30% resolved
                    resolution_hours = random.randint(24, 168)
                else:
                    is_resolved = random.random() < 0.60
                    resolution_hours = random.randint(1, 48)
                
                alert_status = "Resolved" if is_resolved else random.choice(["Fired", "Acknowledged", "Investigating"])
                
                # Generate resolved time if applicable
                resolved_time = None
                if is_resolved:
                    resolved_time = (alert_data["fired_time"] + timedelta(hours=resolution_hours)).isoformat() + "Z"
                
                # Generate email body
                email_body = generator.generate_email_body(alert_data, env)
                estimated_mttr = email_body["estimated_mttr"]
                
                # Prepare data for insertion
                insert_data = (
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
                    alert_data["subscription_id"],
                    scenario_type,
                    estimated_mttr
                )
                
                # Insert into all alerts table
                cursor.execute("""
                    INSERT INTO azure_alerts (
                        alert_id, alert_name, alert_type, severity, environment,
                        alert_status, fired_time, resolved_time, alert_payload,
                        email_body, resource_id, subscription_id, scenario_type, estimated_mttr
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, insert_data)
                
                # Add to all alerts list
                all_alerts.append({
                    "alert_id": alert_id,
                    "alert_name": alert_data["alert_name"],
                    "alert_type": alert_data["alert_type"],
                    "severity": alert_data["severity"],
                    "environment": alert_data["environment"],
                    "alert_status": alert_status,
                    "fired_time": alert_data["fired_time"].isoformat() + "Z",
                    "resolved_time": resolved_time,
                    "alert_payload": alert_data["alert_payload"],
                    "email_body": email_body,
                    "resource_id": alert_data["resource_id"],
                    "subscription_id": alert_data["subscription_id"],
                    "scenario_type": scenario_type,
                    "estimated_mttr": estimated_mttr
                })
                records_created["all"] += 1
                
                # Insert into scenario-specific table
                table_name = f"azure_alerts_{scenario_type}"
                cursor.execute(f"""
                    INSERT INTO {table_name} (
                        alert_id, alert_name, alert_type, severity, environment,
                        alert_status, fired_time, resolved_time, alert_payload,
                        email_body, resource_id, subscription_id, scenario_type, estimated_mttr
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, insert_data)
                
                # Add to scenario-specific list
                alert_record = {
                    "alert_id": alert_id,
                    "alert_name": alert_data["alert_name"],
                    "alert_type": alert_data["alert_type"],
                    "severity": alert_data["severity"],
                    "environment": alert_data["environment"],
                    "alert_status": alert_status,
                    "fired_time": alert_data["fired_time"].isoformat() + "Z",
                    "resolved_time": resolved_time,
                    "alert_payload": alert_data["alert_payload"],
                    "email_body": email_body,
                    "resource_id": alert_data["resource_id"],
                    "subscription_id": alert_data["subscription_id"],
                    "scenario_type": scenario_type,
                    "estimated_mttr": estimated_mttr
                }
                
                if scenario_type == "best":
                    best_alerts.append(alert_record)
                elif scenario_type == "good":
                    good_alerts.append(alert_record)
                elif scenario_type == "worst":
                    worst_alerts.append(alert_record)
                
                records_created[scenario_type] += 1
                
                if records_created["all"] % 200 == 0:
                    print(f"  Progress: {records_created['all']} total records created...")
    
    conn.commit()
    
    # Export to JSON files
    print("\n" + "=" * 80)
    print("EXPORTING TO JSON FILES")
    print("=" * 80)
    
    json_files = {
        "azure_alerts_all.json": all_alerts,
        "azure_alerts_best.json": best_alerts,
        "azure_alerts_good.json": good_alerts,
        "azure_alerts_worst.json": worst_alerts
    }
    
    for filename, data in json_files.items():
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Created: {filename} ({len(data)} records)")
    
    # Print detailed statistics
    print("\n" + "=" * 80)
    print("DATABASE STATISTICS")
    print("=" * 80)
    
    for table in ['azure_alerts', 'azure_alerts_best', 'azure_alerts_good', 'azure_alerts_worst']:
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
        
        # Alert type distribution
        cursor.execute(f"""
            SELECT alert_type, COUNT(*) as count
            FROM {table}
            GROUP BY alert_type
        """)
        print("  Alert Type Distribution:")
        for alert_type, count in cursor.fetchall():
            print(f"    {alert_type}: {count} records")
        
        # Severity distribution
        cursor.execute(f"""
            SELECT severity, COUNT(*) as count
            FROM {table}
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'Sev0' THEN 1
                    WHEN 'Sev1' THEN 2
                    WHEN 'Sev2' THEN 3
                    WHEN 'Sev3' THEN 4
                END
        """)
        print("  Severity Distribution:")
        for severity, count in cursor.fetchall():
            print(f"    {severity}: {count} records")
        
        # Status distribution
        cursor.execute(f"""
            SELECT alert_status, COUNT(*) as count
            FROM {table}
            GROUP BY alert_status
        """)
        print("  Status Distribution:")
        for status, count in cursor.fetchall():
            print(f"    {status}: {count} records")
        
        # Average MTTR
        cursor.execute(f"""
            SELECT ROUND(AVG(estimated_mttr), 2) as avg_mttr
            FROM {table}
        """)
        avg_mttr = cursor.fetchone()[0]
        print(f"  Average Estimated MTTR: {avg_mttr} minutes")
    
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
    generate_alerts(1000)
