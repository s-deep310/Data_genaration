# database_setup.py
import sqlite3
from datetime import datetime
import hashlib
import secrets

class RBACDatabase:
    """Initialize and manage RBAC database schema"""
    
    def __init__(self, db_path='incident_management.db'):
        self.db_path = db_path
        self.conn = None
        
    def connect(self):
        """Establish database connection"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Access columns by name
        return self.conn
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def create_schema(self):
        """Create all RBAC tables"""
        cursor = self.conn.cursor()
        
        # Users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(255),
            department VARCHAR(100),
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        ''')
        
        # Roles table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS roles (
            role_id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_name VARCHAR(100) UNIQUE NOT NULL,
            description TEXT,
            priority_level INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Permissions table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS permissions (
            permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
            permission_name VARCHAR(100) UNIQUE NOT NULL,
            resource VARCHAR(100) NOT NULL,
            action VARCHAR(50) NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Role-Permission mapping
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
        )
        ''')
        
        # User-Role mapping
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            assigned_by INTEGER,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_by) REFERENCES users(user_id)
        )
        ''')
        
        # Incidents table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_code VARCHAR(50) UNIQUE NOT NULL,
            title VARCHAR(500) NOT NULL,
            description TEXT,
            severity VARCHAR(20) NOT NULL,
            status VARCHAR(50) DEFAULT 'open',
            source VARCHAR(100),
            affected_service VARCHAR(255),
            assigned_to INTEGER,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            FOREIGN KEY (assigned_to) REFERENCES users(user_id),
            FOREIGN KEY (created_by) REFERENCES users(user_id)
        )
        ''')
        
        # Incident logs
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            log_data TEXT NOT NULL,
            log_type VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
        )
        ''')
        
        # Audit trail
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action VARCHAR(100) NOT NULL,
            resource VARCHAR(100) NOT NULL,
            resource_id INTEGER,
            details TEXT,
            ip_address VARCHAR(45),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
        ''')
        
        # AI recommendations
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_recommendations (
            recommendation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            recommendation_type VARCHAR(100),
            recommendation_data TEXT NOT NULL,
            confidence_score FLOAT,
            executed_by INTEGER,
            executed_at TIMESTAMP,
            execution_status VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
            FOREIGN KEY (executed_by) REFERENCES users(user_id)
        )
        ''')
        
        self.conn.commit()
        print("✅ Database schema created successfully")
    
    def seed_default_data(self):
        """Insert default roles and permissions"""
        cursor = self.conn.cursor()
        
        # Define default roles
        roles = [
            ('Viewer', 'Read-only access to incidents and reports', 1),
            ('L1_Engineer', 'First-line incident responders', 2),
            ('L2_Engineer', 'Advanced troubleshooting and diagnostics', 3),
            ('L3_Engineer', 'Senior engineers with remediation access', 4),
            ('Incident_Manager', 'Incident coordination and escalation', 5),
            ('Admin', 'Full system administration access', 6)
        ]
        
        cursor.executemany('''
        INSERT OR IGNORE INTO roles (role_name, description, priority_level)
        VALUES (?, ?, ?)
        ''', roles)
        
        # Define permissions
        permissions = [
            ('view_incidents', 'incidents', 'view', 'View incident details'),
            ('create_incidents', 'incidents', 'create', 'Create new incidents'),
            ('update_incidents', 'incidents', 'update', 'Update incident information'),
            ('delete_incidents', 'incidents', 'delete', 'Delete incidents'),
            ('acknowledge_incidents', 'incidents', 'acknowledge', 'Acknowledge incidents'),
            ('assign_incidents', 'incidents', 'assign', 'Assign incidents to users'),
            ('escalate_incidents', 'incidents', 'escalate', 'Escalate incidents'),
            ('resolve_incidents', 'incidents', 'resolve', 'Mark incidents as resolved'),
            ('close_incidents', 'incidents', 'close', 'Close incidents'),
            ('view_logs', 'logs', 'view', 'View incident logs'),
            ('analyze_logs', 'logs', 'analyze', 'Run AI analysis on logs'),
            ('view_ai_recommendations', 'ai_recommendations', 'view', 'View AI recommendations'),
            ('execute_ai_recommendations', 'ai_recommendations', 'execute', 'Execute AI remediation'),
            ('approve_ai_actions', 'ai_recommendations', 'approve', 'Approve AI actions'),
            ('view_users', 'users', 'view', 'View user list'),
            ('create_users', 'users', 'create', 'Create new users'),
            ('update_users', 'users', 'update', 'Update user information'),
            ('delete_users', 'users', 'delete', 'Delete users'),
            ('assign_roles', 'users', 'assign_roles', 'Assign roles to users'),
            ('view_audit_logs', 'audit_logs', 'view', 'View audit trail'),
            ('view_metrics', 'metrics', 'view', 'View system metrics'),
            ('configure_system', 'system', 'configure', 'Configure system settings')
        ]
        
        cursor.executemany('''
        INSERT OR IGNORE INTO permissions (permission_name, resource, action, description)
        VALUES (?, ?, ?, ?)
        ''', permissions)
        
        self.conn.commit()
        
        # Assign permissions to roles
        self._assign_role_permissions(cursor)
        
        print("✅ Default roles and permissions seeded successfully")
    
    def _assign_role_permissions(self, cursor):
        """Map permissions to roles"""
        
        role_perms = {
            'Viewer': [
                'view_incidents', 'view_logs', 'view_ai_recommendations', 'view_metrics'
            ],
            'L1_Engineer': [
                'view_incidents', 'acknowledge_incidents', 'update_incidents',
                'view_logs', 'view_ai_recommendations', 'view_metrics'
            ],
            'L2_Engineer': [
                'view_incidents', 'acknowledge_incidents', 'update_incidents',
                'assign_incidents', 'view_logs', 'analyze_logs',
                'view_ai_recommendations', 'execute_ai_recommendations', 'view_metrics'
            ],
            'L3_Engineer': [
                'view_incidents', 'create_incidents', 'update_incidents',
                'acknowledge_incidents', 'assign_incidents', 'escalate_incidents',
                'resolve_incidents', 'view_logs', 'analyze_logs',
                'view_ai_recommendations', 'execute_ai_recommendations',
                'approve_ai_actions', 'view_metrics'
            ],
            'Incident_Manager': [
                'view_incidents', 'create_incidents', 'update_incidents',
                'delete_incidents', 'acknowledge_incidents', 'assign_incidents',
                'escalate_incidents', 'resolve_incidents', 'close_incidents',
                'view_logs', 'analyze_logs', 'view_ai_recommendations',
                'execute_ai_recommendations', 'approve_ai_actions',
                'view_users', 'view_audit_logs', 'view_metrics'
            ],
            'Admin': [
                'view_incidents', 'create_incidents', 'update_incidents', 'delete_incidents',
                'acknowledge_incidents', 'assign_incidents', 'escalate_incidents',
                'resolve_incidents', 'close_incidents', 'view_logs', 'analyze_logs',
                'view_ai_recommendations', 'execute_ai_recommendations', 'approve_ai_actions',
                'view_users', 'create_users', 'update_users', 'delete_users',
                'assign_roles', 'view_audit_logs', 'view_metrics', 'configure_system'
            ]
        }
        
        for role_name, perms in role_perms.items():
            cursor.execute('SELECT role_id FROM roles WHERE role_name = ?', (role_name,))
            role_result = cursor.fetchone()
            if not role_result:
                continue
            role_id = role_result[0]
            
            for perm_name in perms:
                cursor.execute('SELECT permission_id FROM permissions WHERE permission_name = ?', 
                             (perm_name,))
                perm_result = cursor.fetchone()
                if not perm_result:
                    continue
                perm_id = perm_result[0]
                
                cursor.execute('''
                INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
                VALUES (?, ?)
                ''', (role_id, perm_id))
        
        self.conn.commit()


if __name__ == '__main__':
    db = RBACDatabase()
    db.connect()
    db.create_schema()
    db.seed_default_data()
    db.close()
    print("\n✅ RBAC Database initialized successfully!")
