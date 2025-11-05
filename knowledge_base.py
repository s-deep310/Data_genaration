import sqlite3
import json
import uuid
import random
from datetime import datetime, timedelta
from pathlib import Path


# Database configuration
DB_PATH = "Cloud_Infrastructure.db"
JSON_OUTPUT_PATH = "knowledge_base.json"


class MultiCloudIncidentKnowledgeBase:
    def __init__(self):
        # Real-world incident patterns from Azure, AWS, and GCP
        self.incident_patterns = {
            "Azure": {
                "Sev0": [
                    {
                        "cause": "Azure SQL Database primary replica failure during region outage",
                        "description": "Primary SQL Database instance in East US region became unresponsive due to Azure datacenter cooling system failure. Geo-replication lag prevented immediate failover, causing 45-minute complete outage.",
                        "impact": "Complete database unavailability affecting 50,000+ concurrent users. All CRUD operations failing. Revenue loss: $125,000. Customer-facing applications completely down.",
                        "remediation": "1. Verify secondary region health: az sql db replica list\n2. Force manual failover: az sql db replica set-primary --name db-name --server secondary-server\n3. Update application connection strings to secondary region\n4. Verify data consistency post-failover\n5. Open Severity A ticket with Microsoft\n6. Implement connection retry logic with exponential backoff\n7. Monitor replication lag continuously",
                        "root_cause": "Azure region experienced power distribution failure. Geo-replication had 3-minute lag due to network congestion. Automatic failover threshold set too conservatively (10-minute grace period).",
                        "prevention": "- Reduce failover threshold to 2 minutes\n- Implement active-active database architecture\n- Use Azure Traffic Manager for automatic region failover\n- Set up zone-redundant database configuration\n- Weekly chaos engineering tests of failover scenarios\n- Multi-region deployment with read replicas",
                        "affected_services": ["Azure SQL Database", "App Service", "API Management", "Front Door"],
                        "business_impact": "Critical - Complete service outage, revenue loss, SLA breach",
                        "estimated_recovery_time": "30-60 minutes",
                        "cloud_provider": "Azure"
                    },
                    {
                        "cause": "Azure AD authentication service outage affecting SSO",
                        "description": "Azure Active Directory authentication endpoint experienced cascading failure due to certificate rotation issue. All OAuth2/OIDC authentication requests timing out or returning 503 errors.",
                        "impact": "Complete authentication failure across all applications. 100,000+ users unable to login. Third-party integrations broken. Mobile app authentication completely non-functional.",
                        "remediation": "1. Verify Azure AD service health: https://status.azure.com\n2. Implement emergency bypass using cached tokens (if available)\n3. Switch to backup authentication provider temporarily\n4. Clear Azure AD token cache\n5. Contact Microsoft Premier Support immediately\n6. Communicate status to all users via status page\n7. Enable emergency access accounts\n8. Monitor authentication success rate metrics",
                        "root_cause": "Microsoft's automated certificate rotation process encountered bug affecting multi-tenant authentication endpoints. Issue compounded by insufficient health checks on certificate validity.",
                        "prevention": "- Implement hybrid authentication with on-premises AD as backup\n- Configure emergency access (break-glass) accounts\n- Set up authentication monitoring with 1-minute resolution\n- Subscribe to Azure Service Health alerts\n- Implement client-side token caching with extended TTL\n- Regular testing of backup authentication paths",
                        "affected_services": ["Azure Active Directory", "All authenticated applications", "Microsoft Graph API", "Office 365 integration"],
                        "business_impact": "Critical - Complete authentication outage, business operations halted",
                        "estimated_recovery_time": "45-90 minutes (dependent on Microsoft)",
                        "cloud_provider": "Azure"
                    },
                    {
                        "cause": "Azure Cosmos DB throttling storm during Black Friday peak",
                        "description": "Cosmos DB request units (RU/s) exceeded provisioned capacity by 400% during flash sale. Aggressive throttling caused 429 errors across entire application stack, cascading to complete service failure.",
                        "impact": "Shopping cart operations failing at 95% rate. Order placement impossible. 200,000+ concurrent users affected. Estimated revenue loss: $500,000/hour during peak sales period.",
                        "remediation": "1. Emergency RU/s increase: az cosmosdb sql container throughput update --max-throughput 100000\n2. Enable serverless burst capacity if available\n3. Implement request queuing with exponential backoff\n4. Deploy read replicas across regions\n5. Optimize queries to reduce RU consumption:\n   - Add composite indexes for common queries\n   - Enable query result caching\n   - Reduce SELECT * queries to specific fields\n6. Scale out to multiple partitions\n7. Monitor RU consumption per operation type",
                        "root_cause": "Traffic forecast underestimated by 300%. Provisioned capacity: 20,000 RU/s, actual need: 80,000+ RU/s. No auto-scaling configured. Query optimization not performed during load testing.",
                        "prevention": "- Enable Cosmos DB autoscale with 10x burst capacity\n- Implement request queuing and circuit breakers\n- Add RU consumption monitoring with alerts at 70%\n- Optimize query patterns to reduce RU usage\n- Load test with 5x expected peak traffic\n- Pre-scale before known high-traffic events\n- Use dedicated throughput for critical containers",
                        "affected_services": ["Cosmos DB", "Shopping Cart API", "Order Processing", "Inventory Service"],
                        "business_impact": "Critical - Revenue loss during peak sales, customer experience destroyed",
                        "estimated_recovery_time": "20-45 minutes",
                        "cloud_provider": "Azure"
                    }
                ],
                "Sev1": [
                    {
                        "cause": "Azure Application Gateway backend pool health probe failures",
                        "description": "App Gateway health probes reporting all backend instances as unhealthy due to probe timeout misconfiguration (5s timeout vs 15s application warmup time). Traffic distribution completely stopped.",
                        "impact": "Zero traffic reaching backend servers despite healthy instances. 404 errors for all users. API calls failing. 25,000 requests/minute being rejected.",
                        "remediation": "1. Check backend health: az network application-gateway show-backend-health\n2. Increase probe timeout: az network application-gateway probe update --timeout 30\n3. Adjust unhealthy threshold to 5 consecutive failures\n4. Update probe interval to 15 seconds\n5. Verify backend NSG allows health probe traffic (IP: 168.63.129.16)\n6. Add /health endpoint optimization to reduce response time\n7. Monitor backend pool health continuously",
                        "root_cause": "Recent deployment increased application startup time from 8s to 18s. Health probe timeout remained at 5s. No staging environment testing of health checks.",
                        "prevention": "- Set health probe timeout to 30 seconds minimum\n- Optimize application startup time\n- Test health probes in staging before production\n- Monitor probe success rate with alerts\n- Implement readiness vs liveness probes\n- Document probe configuration standards",
                        "affected_services": ["Application Gateway", "Backend VM Scale Set", "Web Application"],
                        "business_impact": "High - Complete traffic disruption despite healthy backends",
                        "estimated_recovery_time": "15-30 minutes",
                        "cloud_provider": "Azure"
                    },
                    {
                        "cause": "Azure Key Vault access policy misconfiguration after RBAC migration",
                        "description": "Migration from access policies to RBAC removed application's permissions to retrieve secrets. All secret retrieval operations failing with 403 Forbidden errors.",
                        "impact": "Application unable to start - all configuration secrets inaccessible. Database connection strings, API keys unavailable. 15 microservices affected. Deployments completely blocked.",
                        "remediation": "1. Grant emergency access: az keyvault set-policy --secret-permissions get list\n2. Or use RBAC: az role assignment create --role 'Key Vault Secrets User'\n3. Verify managed identity has correct permissions\n4. Update application configuration to use correct identity\n5. Test secret retrieval: az keyvault secret show --name db-connection\n6. Restart affected applications to reload secrets\n7. Audit all Key Vault access policies",
                        "root_cause": "RBAC migration script failed to map existing access policies to equivalent role assignments. Manual assumption that default permissions would carry over.",
                        "prevention": "- Test RBAC migration in non-production first\n- Create permission mapping documentation\n- Use managed identities exclusively\n- Implement secret access monitoring and alerts\n- Maintain emergency break-glass access\n- Automated testing of secret retrieval in CI/CD",
                        "affected_services": ["Key Vault", "All applications using secrets", "CI/CD pipelines"],
                        "business_impact": "High - Application startup failures, deployment blocked",
                        "estimated_recovery_time": "20-40 minutes",
                        "cloud_provider": "Azure"
                    }
                ],
                "Sev2": [
                    {
                        "cause": "Azure Monitor Log Analytics daily ingestion cap reached",
                        "description": "Log Analytics workspace hit 10GB daily cap at 2 PM due to verbose application logging. New logs being dropped, creating monitoring blind spots for remaining 10 hours of day.",
                        "impact": "Missing logs for troubleshooting production issues. Alert rules not triggering due to missing data. Compliance concern for audit logs. Operations team working blind.",
                        "remediation": "1. Increase daily cap: az monitor log-analytics workspace update --quota 20\n2. Identify top log sources: Heartbeat | summarize count() by Computer\n3. Disable verbose logging in production apps\n4. Implement log sampling for high-volume sources\n5. Archive older logs to storage account\n6. Optimize KQL queries for efficiency\n7. Set up cap warnings at 80% threshold",
                        "root_cause": "Debug-level logging accidentally enabled in production deployment. Single API endpoint generating 65% of daily log volume. No log governance policy enforced.",
                        "prevention": "- Environment-specific log levels (Production: Warning+)\n- Implement structured logging with severity filtering\n- Set daily cap alerts at 70%, 85%, 95%\n- Regular review of log volume by source\n- Automated log level validation in deployments\n- Log sampling for high-frequency events",
                        "affected_services": ["Log Analytics", "Application Insights", "Azure Monitor"],
                        "business_impact": "Medium - Monitoring blind spots, compliance risk",
                        "estimated_recovery_time": "2-4 hours",
                        "cloud_provider": "Azure"
                    }
                ],
                "Sev3": [
                    {
                        "cause": "Azure resource tags missing for 40% of resources",
                        "description": "Cost allocation report showing $85,000 monthly spend with untagged resources. Unable to properly chargeback costs to departments and projects.",
                        "impact": "Inaccurate cost center attribution. Budget planning challenges. Finance unable to validate department spending. Compliance audit finding.",
                        "remediation": "1. Generate untagged resource report: az resource list --query \"[?tags==null]\"\n2. Identify owners via activity logs\n3. Apply standard tags: Environment, CostCenter, Owner, Project, Application\n4. Bulk tag using PowerShell/CLI scripts\n5. Implement Azure Policy to enforce tagging\n6. Create tag governance documentation\n7. Schedule monthly tag compliance reviews",
                        "root_cause": "No tagging governance policy enforced at creation time. Manual resource provisioning without standards. Lack of organizational tagging requirements.",
                        "prevention": "- Azure Policy: Deny deployment without required tags\n- Tag inheritance from resource groups\n- Include tags in all IaC templates\n- Automated tag compliance scanning (weekly)\n- Training on tagging importance and standards\n- Cost management dashboard by tag",
                        "affected_services": ["All Azure resources", "Cost Management", "Governance"],
                        "business_impact": "Low - Cost tracking and compliance impact only",
                        "estimated_recovery_time": "2-5 days (administrative)",
                        "cloud_provider": "Azure"
                    }
                ]
            },
            "AWS": {
                "Sev0": [
                    {
                        "cause": "AWS RDS Multi-AZ failover failure due to storage full",
                        "description": "RDS primary instance storage reached 100% capacity. Automatic failover to standby failed because standby replica also at capacity. Database entered read-only mode, then crashed.",
                        "impact": "Complete database outage for 2 hours. All write operations failing. Application in read-only mode unable to process orders. 75,000 active users affected. Revenue loss: $200,000.",
                        "remediation": "1. Enable storage autoscaling: aws rds modify-db-instance --allocated-storage 1000 --apply-immediately\n2. Force manual failover after storage increased\n3. Delete old transaction logs to free space\n4. Optimize database: VACUUM FULL (PostgreSQL) or OPTIMIZE TABLE (MySQL)\n5. Implement data archival for old records\n6. Increase IOPS if storage performance bottleneck\n7. Monitor storage metrics with CloudWatch alarms",
                        "root_cause": "Storage autoscaling not enabled. Transaction log retention set to 30 days without size limit. Data growth from 200GB to 950GB in 3 months not monitored. No capacity planning process.",
                        "prevention": "- Enable RDS storage autoscaling with 20% threshold\n- Set CloudWatch alarms at 70%, 85%, 95% storage capacity\n- Implement automated data archival (>90 days to S3)\n- Reduce transaction log retention to 7 days\n- Monthly capacity planning reviews\n- Enable Enhanced Monitoring for detailed metrics",
                        "affected_services": ["RDS Database", "Application Servers", "Lambda functions", "API Gateway"],
                        "business_impact": "Critical - Complete database failure, extended outage, revenue loss",
                        "estimated_recovery_time": "90-180 minutes",
                        "cloud_provider": "AWS"
                    },
                    {
                        "cause": "AWS Lambda concurrent execution limit exhaustion during DDoS",
                        "description": "Malicious traffic spike triggered 10,000+ Lambda concurrent executions, hitting account limit of 1,000. All Lambda functions throttled including critical authentication and payment processing.",
                        "impact": "Complete Lambda-based application failure. API Gateway returning 429 errors. Payment processing down. Authentication failing. Legitimate users unable to access application.",
                        "remediation": "1. Request immediate limit increase: AWS Support Console -> Service Quotas\n2. Implement API Gateway throttling: 100 requests/second per API key\n3. Enable AWS WAF rules to block attack patterns\n4. Set reserved concurrency for critical functions\n5. Implement exponential backoff in clients\n6. Deploy DDoS mitigation: AWS Shield Advanced\n7. Add CloudFront with rate limiting\n8. Monitor Lambda throttles: ThrottledInvocations metric",
                        "root_cause": "No rate limiting on public APIs. Lambda concurrent execution limit not increased from default 1,000. No DDoS protection configured. Insufficient monitoring of invocation rates.",
                        "prevention": "- Request concurrent execution limit increase to 10,000\n- Set reserved concurrency for critical functions (200 reserved)\n- Implement API Gateway usage plans with throttling\n- Enable AWS WAF with rate-based rules\n- Deploy AWS Shield Standard (automatic) or Advanced\n- CloudFront with geographic restrictions\n- Monitor ConcurrentExecutions metric with alarms",
                        "affected_services": ["Lambda Functions", "API Gateway", "DynamoDB", "Authentication"],
                        "business_impact": "Critical - Complete application outage, payment processing failure",
                        "estimated_recovery_time": "60-120 minutes",
                        "cloud_provider": "AWS"
                    },
                    {
                        "cause": "AWS S3 bucket accidentally deleted via CLI command",
                        "description": "Production S3 bucket containing customer uploads and application assets permanently deleted by engineer running aws s3 rb --force command on wrong terminal. No MFA delete enabled. 5TB data lost.",
                        "impact": "All customer-uploaded files inaccessible (10M+ files). Application images/videos broken. User-generated content completely lost. Potential legal liability for data loss.",
                        "remediation": "1. Check S3 versioning status immediately\n2. If versioning enabled: Restore from version history\n3. If not: Restore from latest backup (if available)\n4. Contact AWS Support for data recovery assistance (within 30 days)\n5. Recreate bucket with exact same name and region\n6. Enable versioning and MFA delete immediately\n7. Implement S3 Object Lock for compliance data\n8. Restore data from backup storage\n9. Update application to handle missing objects gracefully",
                        "root_cause": "No S3 versioning enabled. No MFA delete protection. No bucket deletion policy preventing accidental removal. Engineer had excessive IAM permissions. No backup strategy for S3 data.",
                        "prevention": "- Enable S3 versioning on all production buckets\n- Enable MFA delete for protection\n- Implement S3 Object Lock for compliance data\n- S3 bucket policy: Deny DeleteBucket action\n- Daily backups to separate AWS account\n- Implement S3 Replication to different region\n- Least privilege IAM: Remove s3:DeleteBucket permission\n- Require approval workflow for destructive operations",
                        "affected_services": ["S3 Storage", "CloudFront CDN", "Application file serving", "User uploads"],
                        "business_impact": "Critical - Permanent data loss, potential legal liability",
                        "estimated_recovery_time": "4-24 hours (depending on backup availability)",
                        "cloud_provider": "AWS"
                    }
                ],
                "Sev1": [
                    {
                        "cause": "AWS EC2 instance type retired, forcing instance stops",
                        "description": "AWS deprecated EC2 instance type (m4.large) with 3-month notice. Automated retirement caused all instances to stop simultaneously during business hours, requiring manual migration.",
                        "impact": "50 EC2 instances stopped. Application capacity reduced by 60%. Severe performance degradation. Manual intervention required to change instance types.",
                        "remediation": "1. Modify instance type immediately: aws ec2 modify-instance-attribute --instance-type m5.large\n2. Start instances: aws ec2 start-instances --instance-ids i-xxx\n3. Use AWS Systems Manager for bulk operations\n4. Update Auto Scaling launch templates\n5. Test application compatibility with new instance type\n6. Update Infrastructure as Code (Terraform/CloudFormation)\n7. Monitor for any performance regressions",
                        "root_cause": "AWS deprecation notice emails ignored/unread. No process for tracking AWS service announcements. Infrastructure not regularly updated to current generation instance types.",
                        "prevention": "- Subscribe to AWS Personal Health Dashboard alerts\n- Monthly review of AWS What's New and deprecation notices\n- Proactive migration to current generation instances\n- Implement instance type flexibility in Auto Scaling\n- Use AWS Trusted Advisor recommendations\n- Maintain infrastructure as code for easy updates",
                        "affected_services": ["EC2 Instances", "Auto Scaling Groups", "Application Tier"],
                        "business_impact": "High - Severe capacity reduction, performance impact",
                        "estimated_recovery_time": "30-90 minutes",
                        "cloud_provider": "AWS"
                    },
                    {
                        "cause": "AWS IAM role trust policy expired, breaking cross-account access",
                        "description": "IAM role used for cross-account S3 access had time-bound trust policy that expired. All third-party data ingestion pipelines failing with Access Denied errors.",
                        "impact": "Data ingestion from partner systems stopped. 24 hours of customer data missing. Analytics dashboards showing stale data. ETL pipelines completely blocked.",
                        "remediation": "1. Update IAM role trust policy: aws iam update-assume-role-policy\n2. Remove time-based conditions or extend expiration\n3. Verify external-id still matches for security\n4. Test role assumption: aws sts assume-role\n5. Restart failed data ingestion jobs\n6. Backfill missing data from partner systems\n7. Validate data completeness in target systems",
                        "root_cause": "Trust policy configured with time-based condition for temporary access that was never removed. No monitoring on cross-account access success/failure rates.",
                        "prevention": "- Avoid time-based conditions in production trust policies\n- Implement IAM policy review calendar\n- Monitor AssumeRole API call success rates\n- Set up CloudWatch alarms for Access Denied errors\n- Document all cross-account access configurations\n- Quarterly audit of IAM roles and policies",
                        "affected_services": ["IAM", "S3 Data Lake", "ETL Pipelines", "Analytics"],
                        "business_impact": "High - Data pipeline failure, analytics impact",
                        "estimated_recovery_time": "45-90 minutes + backfill time",
                        "cloud_provider": "AWS"
                    }
                ],
                "Sev2": [
                    {
                        "cause": "AWS CloudWatch Logs retention causing unexpected costs",
                        "description": "CloudWatch Logs retention set to 'Never Expire' resulted in 5TB of accumulated logs over 2 years. Monthly CloudWatch costs increased from $500 to $4,500.",
                        "impact": "Budget overrun of $4,000/month. Finance escalation. No immediate service impact but unsustainable cost growth.",
                        "remediation": "1. Set retention policies: aws logs put-retention-policy --retention-in-days 30\n2. Export old logs to S3: aws logs create-export-task\n3. Delete old log groups not needed: aws logs delete-log-group\n4. Implement log sampling for verbose applications\n5. Archive compliance logs to S3 Glacier\n6. Create cost anomaly alerts in Cost Explorer\n7. Review log group retention monthly",
                        "root_cause": "Default CloudWatch Logs retention is 'Never Expire'. No cost governance policy for logging. Lack of log retention requirements from compliance team.",
                        "prevention": "- Set organization-wide default retention (30-90 days)\n- Use S3 for long-term log archival (cheaper)\n- Implement log streaming to S3 via Kinesis Firehose\n- Enable cost anomaly detection for CloudWatch\n- Monthly cost optimization reviews\n- Tag log groups with retention requirements",
                        "affected_services": ["CloudWatch Logs", "Cost Management"],
                        "business_impact": "Medium - Cost overrun, budget impact",
                        "estimated_recovery_time": "4-8 hours (administrative)",
                        "cloud_provider": "AWS"
                    }
                ],
                "Sev3": [
                    {
                        "cause": "AWS EBS snapshots not deleted after AMI cleanup",
                        "description": "Automated AMI cleanup process deleted old AMIs but orphaned underlying EBS snapshots. 200+ snapshots accumulating monthly, costing $800/month unnecessarily.",
                        "impact": "Wasted storage costs. No immediate functional impact. Resource sprawl and compliance concerns.",
                        "remediation": "1. Identify orphaned snapshots: aws ec2 describe-snapshots --owner-ids self\n2. Cross-reference with existing AMIs\n3. Delete orphaned snapshots: aws ec2 delete-snapshot\n4. Create Lambda function for automated cleanup\n5. Tag snapshots with AMI reference for tracking\n6. Set up cost allocation by resource type\n7. Schedule monthly orphaned resource reviews",
                        "root_cause": "AMI deletion doesn't automatically delete associated snapshots. Cleanup scripts only targeted AMIs. No awareness of snapshot lifecycle management.",
                        "prevention": "- Implement AWS Data Lifecycle Manager for automated snapshot management\n- Tag snapshots with AMI ID and deletion date\n- Lambda function to clean orphaned snapshots weekly\n- Use AWS Config rules to detect orphaned resources\n- Monthly cost review by resource type\n- Document snapshot retention policies",
                        "affected_services": ["EBS Snapshots", "Cost Management"],
                        "business_impact": "Low - Cost waste, no service impact",
                        "estimated_recovery_time": "2-4 hours (administrative)",
                        "cloud_provider": "AWS"
                    }
                ]
            },
            "GCP": {
                "Sev0": [
                    {
                        "cause": "GCP Cloud SQL automatic maintenance window caused unexpected failover",
                        "description": "Cloud SQL scheduled maintenance triggered automatic failover during peak business hours (configured maintenance window not honored due to critical security patch). Primary instance offline for 12 minutes.",
                        "impact": "Database connection failures. 8,000 transactions failed. Application showing errors to all users. Payment processing halted during peak hour. Revenue loss: $45,000.",
                        "remediation": "1. Verify failover completed: gcloud sql operations list\n2. Check connection pool status - drain and reconnect\n3. Update connection strings if IP changed\n4. Verify replica promotion successful\n5. Monitor replication lag: gcloud sql instances describe\n6. Review failed transactions and initiate recovery\n7. Contact Google Cloud Support for maintenance clarification\n8. Update maintenance window to 2-6 AM local time",
                        "root_cause": "Critical security patch required immediate application, overriding maintenance window preference. Application not designed for automatic reconnection after failover. Connection pooling had 30-second timeout.",
                        "prevention": "- Configure maintenance window during off-peak hours (verified)\n- Implement automatic connection retry with exponential backoff\n- Enable Cloud SQL high availability for faster failover\n- Test failover scenarios in staging environment monthly\n- Subscribe to GCP maintenance notifications\n- Implement circuit breaker pattern for database connections\n- Use Cloud SQL Proxy for automatic connection management",
                        "affected_services": ["Cloud SQL", "App Engine", "Cloud Run", "Kubernetes Engine"],
                        "business_impact": "Critical - Transaction failures, revenue loss during peak period",
                        "estimated_recovery_time": "15-30 minutes",
                        "cloud_provider": "GCP"
                    },
                    {
                        "cause": "GCP Compute Engine quota exhaustion preventing auto-scaling",
                        "description": "Auto-scaling group unable to provision new instances during traffic spike. Regional CPU quota (500 cores) completely consumed. Existing instances at 100% CPU causing application timeouts.",
                        "impact": "Application unable to scale horizontally. Response times degraded from 200ms to 15 seconds. 40% of requests timing out. Customer complaints increasing exponentially.",
                        "remediation": "1. Request immediate quota increase: GCP Console -> IAM -> Quotas\n2. Check current usage: gcloud compute regions describe us-central1\n3. Scale up existing instances (vertical scaling): gcloud compute instances set-machine-type\n4. Delete idle/dev instances to free quota\n5. Distribute load to different region if possible\n6. Implement request queuing with Cloud Tasks\n7. Enable Cloud CDN to reduce origin load\n8. Contact Google Cloud Support for emergency quota increase",
                        "root_cause": "Regional quota not increased proactively before marketing campaign. Auto-scaling configured for 3x normal capacity but quota only supported 2x. No quota monitoring alerts configured.",
                        "prevention": "- Request quota increases 2 weeks before major events\n- Set up quota monitoring with Cloud Monitoring alerts at 80%\n- Use multiple regions for geographical distribution\n- Implement quota buffer (request 150% of expected peak)\n- Document quota increase procedures\n- Use Managed Instance Groups across regions\n- Regular capacity planning reviews",
                        "affected_services": ["Compute Engine", "Managed Instance Groups", "Load Balancer"],
                        "business_impact": "Critical - Application performance severely degraded, scaling blocked",
                        "estimated_recovery_time": "45-120 minutes (depending on quota approval)",
                        "cloud_provider": "GCP"
                    },
                    {
                        "cause": "GCP Cloud Storage bucket lifecycle policy accidentally deleted production data",
                        "description": "Misconfigured lifecycle policy deleted objects older than 30 days, including critical production backups and customer data archives. 2TB of data permanently removed.",
                        "impact": "Loss of database backups from last 6 months. Customer file archives deleted. Unable to restore systems in case of failure. Compliance violation for data retention.",
                        "remediation": "1. Immediately disable lifecycle policy: gsutil lifecycle set /dev/null gs://bucket\n2. Check if Object Versioning enabled: gsutil versioning get gs://bucket\n3. Restore from object versions if available\n4. Contact Google Cloud Support for data recovery (30-day window)\n5. Restore from off-site backups if available\n6. Implement Object Lock for compliance data\n7. Audit all bucket lifecycle policies across project\n8. Create incident report for compliance team",
                        "root_cause": "Lifecycle policy intended for development bucket applied to production bucket. No testing in staging. Object versioning not enabled. No separate backup verification process.",
                        "prevention": "- Enable Object Versioning on all production buckets\n- Implement bucket naming convention (prod-*, dev-*)\n- Require peer review for lifecycle policy changes\n- Test lifecycle policies in non-production first\n- Use separate GCP projects for prod and non-prod\n- Implement retention locks for compliance data\n- Daily backup verification with checksums\n- Cross-region backup replication",
                        "affected_services": ["Cloud Storage", "Backup Systems", "Data Archives"],
                        "business_impact": "Critical - Data loss, compliance violation, backup recovery capability lost",
                        "estimated_recovery_time": "24-72 hours (depending on recovery method)",
                        "cloud_provider": "GCP"
                    }
                ],
                "Sev1": [
                    {
                        "cause": "GCP Cloud Functions cold start latency exceeding API timeout",
                        "description": "Cloud Functions experiencing 8-12 second cold starts for Node.js 18 runtime. API Gateway timeout set to 5 seconds causing all initial requests to fail with 504 errors.",
                        "impact": "30% of API requests failing during cold starts. User experience severely degraded. Mobile app showing frequent timeout errors. Customer support tickets increased 300%.",
                        "remediation": "1. Increase API timeout: gcloud api-gateway gateways update --timeout=30s\n2. Implement min-instances for critical functions: gcloud functions deploy --min-instances=5\n3. Optimize function package size - remove unused dependencies\n4. Use lighter-weight runtime (Python 3.11 vs Node.js for faster cold starts)\n5. Implement connection pooling for database connections\n6. Enable Cloud Functions 2nd gen for better cold start performance\n7. Add warmup function triggered every 5 minutes\n8. Monitor cold start metrics in Cloud Monitoring",
                        "root_cause": "Cloud Functions on 1st gen with heavy dependencies (400MB deployment). No minimum instances configured. API timeout too aggressive. Runtime cold start characteristics not tested.",
                        "prevention": "- Migrate to Cloud Functions 2nd gen (faster cold starts)\n- Set min-instances for production functions (3-5 instances)\n- Optimize deployment package size (<50MB)\n- Increase API Gateway timeouts to 30 seconds\n- Use Cloud Run for HTTP-triggered workloads (better cold start)\n- Implement lazy loading for dependencies\n- Cold start performance testing in CI/CD",
                        "affected_services": ["Cloud Functions", "API Gateway", "Mobile Backend"],
                        "business_impact": "High - Significant API failure rate, poor user experience",
                        "estimated_recovery_time": "30-60 minutes",
                        "cloud_provider": "GCP"
                    },
                    {
                        "cause": "GCP BigQuery query costs exceeded monthly budget quota",
                        "description": "Runaway analytical query scanned 50TB of data due to missing partition filter. Query cost $2,500. Daily budget quota of $500 exceeded, halting all BigQuery operations for the day.",
                        "impact": "All analytics dashboards frozen. Data pipeline jobs failing. Business intelligence reports unavailable. Data science team unable to work.",
                        "remediation": "1. Increase daily quota temporarily: GCP Console -> BigQuery -> Quotas\n2. Cancel running expensive queries: bq cancel <job_id>\n3. Identify query author and optimize query with partitioning\n4. Add WHERE clause for partition filter: WHERE DATE(timestamp) >= '2025-10-01'\n5. Estimate query cost before running: bq query --dry_run\n6. Implement query result caching\n7. Create materialized views for common queries\n8. Set up cost alerts at 80% of budget",
                        "root_cause": "Query written without partition filter scanned entire 3-year dataset. No cost controls on individual queries. Users not trained on BigQuery cost optimization. No query cost estimation before execution.",
                        "prevention": "- Require partition filters for all partitioned tables\n- Implement custom cost quotas per user/project\n- Enable query cost estimation in BI tools\n- Training on BigQuery cost optimization best practices\n- Use clustering in addition to partitioning\n- Create cost dashboards visible to all users\n- Implement query result caching (24-hour TTL)\n- Use BigQuery BI Engine for sub-second queries",
                        "affected_services": ["BigQuery", "Data Analytics", "Business Intelligence"],
                        "business_impact": "High - Analytics completely blocked, business decisions delayed",
                        "estimated_recovery_time": "4-8 hours (quota reset next day)",
                        "cloud_provider": "GCP"
                    }
                ],
                "Sev2": [
                    {
                        "cause": "GCP Cloud Logging retention causing storage costs spike",
                        "description": "Default 30-day log retention across all projects resulted in 8TB of accumulated logs. Monthly logging costs increased from $200 to $3,200 without warning.",
                        "impact": "Budget overrun. No immediate service impact but unsustainable cost trajectory. Finance team escalation required.",
                        "remediation": "1. Update log retention: gcloud logging sinks update --log-filter='retention-days=7'\n2. Create log sink to export to Cloud Storage: gcloud logging sinks create\n3. Delete old logs: gcloud logging logs delete\n4. Implement log sampling for verbose sources\n5. Configure Cloud Storage lifecycle to move logs to Coldline after 90 days\n6. Set up budget alerts in Cloud Billing\n7. Review log severity levels (reduce INFO to WARNING in prod)",
                        "root_cause": "Default 30-day retention applied to all logs without cost consideration. Verbose debug logging enabled in production. No cost monitoring for logging services.",
                        "prevention": "- Set retention to 7 days for non-compliance logs\n- Export logs to Cloud Storage (much cheaper)\n- Implement environment-based log levels (WARN+ in prod)\n- Use log exclusion filters for noisy sources\n- Enable cost anomaly detection alerts\n- Monthly review of logging costs by project\n- Log sampling for high-volume applications",
                        "affected_services": ["Cloud Logging", "Cost Management"],
                        "business_impact": "Medium - Significant cost increase, budget impact",
                        "estimated_recovery_time": "4-6 hours (administrative)",
                        "cloud_provider": "GCP"
                    }
                ],
                "Sev3": [
                    {
                        "cause": "GCP Compute Engine instances running without labels",
                        "description": "Cost allocation report showing $15,000 monthly compute spend without proper labeling. Unable to attribute costs to teams, projects, or environments.",
                        "impact": "Inaccurate cost attribution. Department chargebacks blocked. Budget planning challenges. Compliance finding in audit.",
                        "remediation": "1. List unlabeled instances: gcloud compute instances list --filter='labels:*'\n2. Identify instance owners from audit logs\n3. Apply standard labels: gcloud compute instances add-labels --labels=env=prod,team=engineering\n4. Create organization policy requiring labels\n5. Bulk label using scripts or Terraform\n6. Create label taxonomy documentation\n7. Set up automated label compliance scanning",
                        "root_cause": "No label governance policy enforced. Manual instance creation without standards. Lack of organizational labeling requirements.",
                        "prevention": "- Organization policy: Require labels on resource creation\n- Label inheritance from folders/projects\n- Include labels in all Terraform modules\n- Automated compliance scanning (weekly)\n- Training on labeling standards and importance\n- Cost breakdown dashboards by label\n- Integration with CMDB via labels",
                        "affected_services": ["Compute Engine", "Cost Management", "Governance"],
                        "business_impact": "Low - Cost tracking impact, administrative burden",
                        "estimated_recovery_time": "1-3 days (administrative)",
                        "cloud_provider": "GCP"
                    }
                ]
            }
        }

    def generate_incident(self, cloud_provider, severity):
        """Generate a realistic incident based on cloud provider and severity"""
        pattern = random.choice(self.incident_patterns[cloud_provider][severity])
        
        # Generate realistic timestamps
        days_ago = random.randint(1, 180)  # Last 6 months
        start_time = datetime.utcnow() - timedelta(days=days_ago, hours=random.randint(0, 23), minutes=random.randint(0, 59))
        
        # Duration based on severity and cloud provider
        duration_ranges = {
            "Sev0": (20, 240),   # 20 min to 4 hours
            "Sev1": (30, 300),   # 30 min to 5 hours
            "Sev2": (60, 600),   # 1 to 10 hours
            "Sev3": (120, 4320)  # 2 hours to 3 days
        }
        
        duration_minutes = random.randint(*duration_ranges[severity])
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        incident = {
            "incident_id": str(uuid.uuid4()),
            "cloud_provider": cloud_provider,
            "severity": severity,
            "cause": pattern["cause"],
            "description": pattern["description"],
            "impact": pattern["impact"],
            "remediation": pattern["remediation"],
            "root_cause": pattern["root_cause"],
            "prevention": pattern["prevention"],
            "affected_services": pattern["affected_services"],
            "business_impact": pattern["business_impact"],
            "estimated_recovery_time": pattern["estimated_recovery_time"],
            "actual_recovery_time": f"{duration_minutes} minutes",
            "start_time": start_time.isoformat() + "Z",
            "end_time": end_time.isoformat() + "Z",
            "detection_method": random.choice(["Monitoring Alert", "Customer Report", "Automated Health Check", "Manual Discovery", "Third-party Monitoring"]),
            "incident_commander": random.choice(["ops-team@company.com", "sre-lead@company.com", "devops-oncall@company.com"]),
            "status": "Resolved",
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
        
        return incident


def create_knowledge_base_table():
    """Create the enhanced incident_knowledge_base table"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Drop existing table to recreate with new schema
    cursor.execute("DROP TABLE IF EXISTS incident_knowledge_base")
    
    cursor.execute("""
    CREATE TABLE incident_knowledge_base (
        incident_id TEXT PRIMARY KEY,
        cloud_provider TEXT NOT NULL,
        severity TEXT NOT NULL,
        cause TEXT NOT NULL,
        description TEXT NOT NULL,
        impact TEXT NOT NULL,
        remediation TEXT NOT NULL,
        root_cause TEXT NOT NULL,
        prevention TEXT NOT NULL,
        affected_services TEXT NOT NULL,
        business_impact TEXT NOT NULL,
        estimated_recovery_time TEXT NOT NULL,
        actual_recovery_time TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        detection_method TEXT NOT NULL,
        incident_commander TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Create indexes for better query performance
    cursor.execute("CREATE INDEX idx_cloud_provider ON incident_knowledge_base(cloud_provider)")
    cursor.execute("CREATE INDEX idx_severity ON incident_knowledge_base(severity)")
    cursor.execute("CREATE INDEX idx_start_time ON incident_knowledge_base(start_time)")
    
    conn.commit()
    conn.close()
    print("✓ Created incident_knowledge_base table with indexes")


def generate_knowledge_base(total_records=500):
    """Generate realistic multi-cloud incident knowledge base data"""
    generator = MultiCloudIncidentKnowledgeBase()
    
    # Cloud provider distribution (realistic for multi-cloud environment)
    cloud_distribution = {
        "Azure": int(total_records * 0.40),  # 40% Azure
        "AWS": int(total_records * 0.35),    # 35% AWS
        "GCP": int(total_records * 0.25)     # 25% GCP
    }
    
    # Severity distribution (realistic for knowledge base)
    severity_distribution = {
        "Sev0": 0.15,  # 15% critical
        "Sev1": 0.25,  # 25% high
        "Sev2": 0.35,  # 35% medium
        "Sev3": 0.25   # 25% low
    }
    
    print("\n" + "="*70)
    print("🌩️  MULTI-CLOUD INCIDENT KNOWLEDGE BASE GENERATOR")
    print("="*70)
    print(f"\n📊 Generating {total_records} incidents across cloud providers:")
    print("-" * 70)
    for cloud, count in cloud_distribution.items():
        print(f"   {cloud:8s}: {count:3d} incidents ({count/total_records*100:.1f}%)")
    
    print("\n📈 Severity distribution per cloud:")
    print("-" * 70)
    for severity, percentage in severity_distribution.items():
        print(f"   {severity}: {percentage*100:.0f}%")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Clear existing data
    cursor.execute("DELETE FROM incident_knowledge_base")
    
    all_incidents = []
    records_created = 0
    
    print("\n⚙️  Generating incidents...")
    print("-" * 70)
    
    for cloud_provider, cloud_count in cloud_distribution.items():
        for severity, sev_percentage in severity_distribution.items():
            count = int(cloud_count * sev_percentage)
            
            for i in range(count):
                incident = generator.generate_incident(cloud_provider, severity)
                
                # Insert into database
                cursor.execute("""
                    INSERT INTO incident_knowledge_base (
                        incident_id, cloud_provider, severity, cause, description, impact,
                        remediation, root_cause, prevention, affected_services,
                        business_impact, estimated_recovery_time, actual_recovery_time,
                        start_time, end_time, detection_method, incident_commander, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident["incident_id"],
                    incident["cloud_provider"],
                    incident["severity"],
                    incident["cause"],
                    incident["description"],
                    incident["impact"],
                    incident["remediation"],
                    incident["root_cause"],
                    incident["prevention"],
                    json.dumps(incident["affected_services"]),
                    incident["business_impact"],
                    incident["estimated_recovery_time"],
                    incident["actual_recovery_time"],
                    incident["start_time"],
                    incident["end_time"],
                    incident["detection_method"],
                    incident["incident_commander"],
                    incident["status"]
                ))
                
                all_incidents.append(incident)
                records_created += 1
                
                if records_created % 100 == 0:
                    print(f"   ✓ Created {records_created}/{total_records} records...")
    
    conn.commit()
    
    # Save to JSON file
    Path(JSON_OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(JSON_OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump({
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_incidents": len(all_incidents),
                "cloud_providers": list(cloud_distribution.keys()),
                "version": "2.0"
            },
            "incidents": all_incidents
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ JSON file saved: {JSON_OUTPUT_PATH}")
    
    # Print detailed summary statistics
    print("\n" + "="*70)
    print("📈 SUMMARY STATISTICS")
    print("="*70)
    
    print("\n1️⃣  By Cloud Provider & Severity:")
    print("-" * 70)
    cursor.execute("""
        SELECT 
            cloud_provider,
            severity,
            COUNT(*) as count,
            ROUND(AVG(CAST((julianday(end_time) - julianday(start_time)) * 24 * 60 AS INTEGER)), 0) as avg_duration_min
        FROM incident_knowledge_base
        GROUP BY cloud_provider, severity
        ORDER BY cloud_provider, 
            CASE severity
                WHEN 'Sev0' THEN 1
                WHEN 'Sev1' THEN 2
                WHEN 'Sev2' THEN 3
                WHEN 'Sev3' THEN 4
            END
    """)
    
    results = cursor.fetchall()
    current_cloud = None
    for cloud, severity, count, avg_duration in results:
        if cloud != current_cloud:
            if current_cloud is not None:
                print()
            print(f"   {cloud}:")
            current_cloud = cloud
        print(f"      {severity}: {count:3d} incidents (Avg recovery: {int(avg_duration):4d} min)")
    
    print("\n2️⃣  Total by Cloud Provider:")
    print("-" * 70)
    cursor.execute("""
        SELECT 
            cloud_provider,
            COUNT(*) as total,
            ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM incident_knowledge_base), 1) as percentage
        FROM incident_knowledge_base
        GROUP BY cloud_provider
        ORDER BY total DESC
    """)
    
    for cloud, total, percentage in cursor.fetchall():
        print(f"   {cloud:8s}: {total:3d} incidents ({percentage:5.1f}%)")
    
    print("\n3️⃣  Detection Methods:")
    print("-" * 70)
    cursor.execute("""
        SELECT 
            detection_method,
            COUNT(*) as count,
            ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM incident_knowledge_base), 1) as percentage
        FROM incident_knowledge_base
        GROUP BY detection_method
        ORDER BY count DESC
    """)
    
    for method, count, percentage in cursor.fetchall():
        print(f"   {method:25s}: {count:3d} ({percentage:5.1f}%)")
    
    conn.close()
    
    print("\n" + "="*70)
    print("✅ KNOWLEDGE BASE GENERATION COMPLETED!")
    print("="*70)
    print(f"   📊 Total incidents: {records_created}")
    print(f"   💾 Database: {DB_PATH}")
    print(f"   📄 JSON export: {JSON_OUTPUT_PATH}")
    print("="*70 + "\n")


if __name__ == "__main__":
    create_knowledge_base_table()
    generate_knowledge_base(total_records=1000)
