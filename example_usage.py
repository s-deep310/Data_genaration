# example_usage.py
from database_setup import RBACDatabase
from rbac_manager import RBACManager
from incident_manager import IncidentManager
import json

def setup_demo():
    """Setup demo database with sample data"""
    # Initialize database
    db = RBACDatabase()
    db.connect()
    db.create_schema()
    db.seed_default_data()
    db.close()
    
    print("✅ Database initialized\n")
    
    # Create users
    rbac = RBACManager()
    rbac.connect()
    
    users = [
        ('john_viewer', 'john@example.com', 'password123', 'John Viewer', 'Operations', 'Viewer'),
        ('alice_l1', 'alice@example.com', 'password123', 'Alice L1', 'Operations', 'L1_Engineer'),
        ('bob_l2', 'bob@example.com', 'password123', 'Bob L2', 'Engineering', 'L2_Engineer'),
        ('carol_l3', 'carol@example.com', 'password123', 'Carol L3', 'Engineering', 'L3_Engineer'),
        ('dave_manager', 'dave@example.com', 'password123', 'Dave Manager', 'Management', 'Incident_Manager'),
        ('eve_admin', 'eve@example.com', 'password123', 'Eve Admin', 'IT', 'Admin')
    ]
    
    for username, email, password, full_name, dept, role in users:
        success, msg, user_id = rbac.create_user(username, email, password, full_name, dept)
        if success:
            rbac.assign_role_to_user(user_id, role, assigned_by=1)
            print(f"✅ Created user: {username} with role {role}")
    
    rbac.close()
    print("\n✅ Demo setup complete!\n")


def demo_rbac_workflow():
    """Demonstrate RBAC workflow"""
    
    print("=" * 60)
    print("RBAC DEMO: Cloud Infrastructure Incident Management")
    print("=" * 60 + "\n")
    
    rbac = RBACManager()
    rbac.connect()
    
    incident_mgr = IncidentManager()
    incident_mgr.connect()
    
    # ==================== Authentication ====================
    print("\n--- Authentication ---")
    success, user_info = rbac.authenticate_user('bob_l2', 'password123')
    
    if not success:
        print("❌ Authentication failed")
        rbac.close()
        incident_mgr.close()
        return
    
    print(f"✅ Authenticated as: {user_info['full_name']} ({user_info['username']})")
    user_id = user_info['user_id']
    
    # Get user roles
    roles = rbac.get_user_roles(user_id)
    print(f"   Roles: {', '.join(roles)}")
    
    # Get user permissions
    permissions = rbac.get_user_permissions(user_id)
    print(f"   Permissions: {len(permissions)} total")
    print(f"   Sample: {', '.join([p['permission_name'] for p in permissions[:5]])}...")
    
    # ==================== Create Incident (L2 Engineer) ====================
    print("\n--- Create Incident (L2 Engineer - Bob) ---")
    
    log_data = json.dumps({
        "timestamp": "2025-11-04T09:15:00Z",
        "severity": "ERROR",
        "service": "api-gateway",
        "message": "High memory usage detected - 95%",
        "host": "prod-api-01"
    })
    
    result = incident_mgr.create_incident(
        user_id=user_id,
        title="High Memory Usage - API Gateway",
        description="API Gateway pod showing 95% memory consumption with increasing response times",
        severity="high",
        affected_service="api-gateway",
        log_data=log_data
    )
    
    if not result['success']:
        print(f"❌ Failed to create incident: {result.get('error', 'Unknown error')}")
        rbac.close()
        incident_mgr.close()
        return
    
    print(f"✅ Incident created: {result['incident_code']}")
    incident_id = result['incident_id']
    
    # ==================== View Incident ====================
    print("\n--- View Incident ---")
    
    result = incident_mgr.view_incident(user_id, incident_id)
    
    if not result['success']:
        print(f"❌ Failed to view incident: {result.get('error', 'Unknown error')}")
    else:
        incident = result['incident']
        print(f"✅ Incident Details:")
        print(f"   Code: {incident['incident_code']}")
        print(f"   Title: {incident['title']}")
        print(f"   Severity: {incident['severity']}")
        print(f"   Status: {incident['status']}")
        print(f"   Access Level: {result['access_level']}")
        print(f"   Logs Available: {len(result['logs'])}")
    
    # ==================== Add AI Recommendation ====================
    print("\n--- Add AI Recommendation (L2 Engineer) ---")
    
    ai_recommendation = {
        "remediation_type": "scale_up",
        "action": "Increase memory limit",
        "details": {
            "current_limit": "2Gi",
            "recommended_limit": "4Gi",
            "reasoning": "Memory usage consistently above 90% for 15 minutes"
        },
        "estimated_impact": "Resolves memory pressure, improves response time"
    }
    
    result = incident_mgr.add_ai_recommendation(
        user_id=user_id,
        incident_id=incident_id,
        recommendation_type="remediation",
        recommendation_data=ai_recommendation,
        confidence_score=0.92
    )
    
    if not result['success']:
        print(f"❌ Failed to add recommendation: {result.get('error', 'Unknown error')}")
        rec_id = None
    else:
        print(f"✅ AI Recommendation added (ID: {result['recommendation_id']})")
        print(f"   Type: Remediation - Scale Up")
        print(f"   Confidence: 92%")
        rec_id = result['recommendation_id']
    
    # ==================== Try to Approve as L2 (Should Fail) ====================
    if rec_id:
        print("\n--- Try to Approve AI Recommendation (L2 Engineer) ---")
        
        result = incident_mgr.approve_ai_recommendation(user_id, rec_id)
        
        if not result['success']:
            print(f"❌ Permission denied: {result.get('error', 'Unknown error')}")
            print(f"   L2 Engineers cannot approve AI actions")
        else:
            print(f"✅ {result['message']}")
    
    # ==================== Switch to L3 Engineer ====================
    print("\n--- Switch User: L3 Engineer (Carol) ---")
    
    success, l3_user = rbac.authenticate_user('carol_l3', 'password123')
    
    if not success:
        print("❌ Authentication failed for L3 Engineer")
    else:
        print(f"✅ Authenticated as: {l3_user['full_name']}")
        l3_user_id = l3_user['user_id']
        
        # Approve AI recommendation
        if rec_id:
            print("\n--- Approve AI Recommendation (L3 Engineer) ---")
            result = incident_mgr.approve_ai_recommendation(l3_user_id, rec_id)
            
            if result['success']:
                print(f"✅ {result['message']}")
            else:
                print(f"❌ {result.get('error', 'Unknown error')}")
    
    # ==================== Assign Incident (Incident Manager) ====================
    print("\n--- Switch User: Incident Manager (Dave) ---")
    
    success, manager_user = rbac.authenticate_user('dave_manager', 'password123')
    
    if not success:
        print("❌ Authentication failed for Incident Manager")
    else:
        print(f"✅ Authenticated as: {manager_user['full_name']}")
        manager_id = manager_user['user_id']
        
        # Assign incident to L3 engineer
        print("\n--- Assign Incident to L3 Engineer ---")
        result = incident_mgr.assign_incident(
            user_id=manager_id,
            incident_id=incident_id,
            assign_to_user_id=l3_user_id
        )
        
        if result['success']:
            print(f"✅ Incident assigned to Carol (L3 Engineer)")
        else:
            print(f"❌ {result.get('error', 'Unknown error')}")
    
    # ==================== Resolve Incident (L3 Engineer) ====================
    print("\n--- Resolve Incident (L3 Engineer - Carol) ---")
    
    result = incident_mgr.resolve_incident(
        user_id=l3_user_id,
        incident_id=incident_id,
        resolution_notes="Increased memory limit to 4Gi. Memory usage now stable at 65%. Response times back to normal."
    )
    
    if result['success']:
        print(f"✅ {result['message']}")
    else:
        print(f"❌ {result.get('error', 'Unknown error')}")
    
    # ==================== List Incidents ====================
    print("\n--- List All Incidents (Viewer - John) ---")
    
    success, viewer_user = rbac.authenticate_user('john_viewer', 'password123')
    
    if not success:
        print("❌ Authentication failed for Viewer")
    else:
        viewer_id = viewer_user['user_id']
        
        result = incident_mgr.list_incidents(viewer_id)
        
        if result['success']:
            print(f"✅ Found {result['count']} incidents")
            for inc in result['incidents']:
                print(f"   - {inc['incident_code']}: {inc['title']} [{inc['status']}]")
        else:
            print(f"❌ {result.get('error', 'Unknown error')}")
    
    # ==================== Audit Trail ====================
    print("\n--- Audit Trail (Admin - Eve) ---")
    
    success, admin_user = rbac.authenticate_user('eve_admin', 'password123')
    
    if not success:
        print("❌ Authentication failed for Admin")
    else:
        admin_id = admin_user['user_id']
        
        if rbac.has_permission(admin_id, 'view_audit_logs'):
            audit_logs = rbac.get_audit_logs(limit=10)
            
            print(f"✅ Recent audit logs ({len(audit_logs)} entries):")
            for log in audit_logs[:5]:
                print(f"   - [{log['timestamp']}] {log['username'] or 'System'}: {log['action']} on {log['resource']}")
        else:
            print("❌ No permission to view audit logs")
    
    # Close connections
    rbac.close()
    incident_mgr.close()
    
    print("\n" + "=" * 60)
    print("Demo completed successfully!")
    print("=" * 60)


if __name__ == '__main__':
    print("Setting up demo database...\n")
    setup_demo()
    
    print("\nRunning RBAC workflow demo...\n")
    demo_rbac_workflow()
