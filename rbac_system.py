import sqlite3
import json
import hashlib
import secrets
import sys
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum
from contextlib import contextmanager
from pathlib import Path


# Database configuration
DB_PATH = "Cloud_Infrastructure.db"


# ============================================================================
# ENUMS FOR RBAC
# ============================================================================

class UserRole(Enum):
    """User roles in the incident management system"""
    ADMIN = "admin"
    SRE_LEAD = "sre_lead"
    SRE_ENGINEER = "sre_engineer"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class Permission(Enum):
    """System permissions"""
    # Incident permissions
    VIEW_INCIDENTS = "view_incidents"
    CREATE_INCIDENTS = "create_incidents"
    UPDATE_INCIDENTS = "update_incidents"
    DELETE_INCIDENTS = "delete_incidents"
    RESOLVE_INCIDENTS = "resolve_incidents"
    
    # Alert permissions
    VIEW_ALERTS = "view_alerts"
    ACKNOWLEDGE_ALERTS = "acknowledge_alerts"
    RESOLVE_ALERTS = "resolve_alerts"
    DELETE_ALERTS = "delete_alerts"
    
    # Knowledge base permissions
    VIEW_KNOWLEDGE_BASE = "view_knowledge_base"
    CREATE_KNOWLEDGE_BASE = "create_knowledge_base"
    UPDATE_KNOWLEDGE_BASE = "update_knowledge_base"
    DELETE_KNOWLEDGE_BASE = "delete_knowledge_base"
    
    # User management permissions
    VIEW_USERS = "view_users"
    CREATE_USERS = "create_users"
    UPDATE_USERS = "update_users"
    DELETE_USERS = "delete_users"
    ASSIGN_ROLES = "assign_roles"
    
    # Analytics and reporting
    VIEW_ANALYTICS = "view_analytics"
    EXPORT_DATA = "export_data"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    
    # System administration
    MANAGE_SYSTEM = "manage_system"
    CONFIGURE_INTEGRATIONS = "configure_integrations"


# Role to permissions mapping
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [p for p in Permission],  # All permissions
    
    UserRole.SRE_LEAD: [
        Permission.VIEW_INCIDENTS, Permission.CREATE_INCIDENTS,
        Permission.UPDATE_INCIDENTS, Permission.DELETE_INCIDENTS,
        Permission.RESOLVE_INCIDENTS,
        Permission.VIEW_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
        Permission.RESOLVE_ALERTS, Permission.DELETE_ALERTS,
        Permission.VIEW_KNOWLEDGE_BASE, Permission.CREATE_KNOWLEDGE_BASE,
        Permission.UPDATE_KNOWLEDGE_BASE, Permission.DELETE_KNOWLEDGE_BASE,
        Permission.VIEW_ANALYTICS, Permission.EXPORT_DATA,
        Permission.VIEW_USERS, Permission.VIEW_AUDIT_LOGS,
        Permission.CONFIGURE_INTEGRATIONS,
    ],
    
    UserRole.SRE_ENGINEER: [
        Permission.VIEW_INCIDENTS, Permission.CREATE_INCIDENTS,
        Permission.UPDATE_INCIDENTS, Permission.RESOLVE_INCIDENTS,
        Permission.VIEW_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
        Permission.RESOLVE_ALERTS,
        Permission.VIEW_KNOWLEDGE_BASE, Permission.CREATE_KNOWLEDGE_BASE,
        Permission.UPDATE_KNOWLEDGE_BASE,
        Permission.VIEW_ANALYTICS, Permission.EXPORT_DATA,
    ],
    
    UserRole.DEVELOPER: [
        Permission.VIEW_INCIDENTS, Permission.CREATE_INCIDENTS,
        Permission.UPDATE_INCIDENTS,
        Permission.VIEW_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
        Permission.VIEW_KNOWLEDGE_BASE,
        Permission.VIEW_ANALYTICS,
    ],
    
    UserRole.VIEWER: [
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_ALERTS,
        Permission.VIEW_KNOWLEDGE_BASE,
        Permission.VIEW_ANALYTICS,
    ],
}


# ============================================================================
# DATABASE CONNECTION MANAGER
# ============================================================================

class DatabaseManager:
    """Singleton database connection manager"""
    _instance = None
    _connection = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        # Ensure directory exists
        db_dir = Path(DB_PATH).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def execute_query(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Execute SELECT query and return results"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute INSERT/UPDATE/DELETE and return affected rows"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.rowcount
    
    def execute_insert(self, query: str, params: tuple = ()) -> str:
        """Execute INSERT and return last row id"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.lastrowid
    
    def table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table_name,)
                )
                return cursor.fetchone() is not None
        except:
            return False


# ============================================================================
# BASE MODEL CLASS (ORM-like)
# ============================================================================

class BaseModel:
    """Base class for all database models"""
    table_name = None
    db = DatabaseManager()
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    @classmethod
    def find_by_id(cls, record_id: str):
        """Find record by ID"""
        try:
            # Ensure table exists
            if not cls.db.table_exists(cls.table_name):
                return None
                
            query = f"SELECT * FROM {cls.table_name} WHERE id = ? OR {cls.table_name.rstrip('s')}_id = ?"
            results = cls.db.execute_query(query, (record_id, record_id))
            if results:
                return cls(**dict(results[0]))
            return None
        except Exception as e:
            print(f"Error in find_by_id: {e}")
            return None
    
    @classmethod
    def find_all(cls, limit: int = 100, offset: int = 0):
        """Find all records with pagination"""
        try:
            # Ensure table exists
            if not cls.db.table_exists(cls.table_name):
                return []
                
            query = f"SELECT * FROM {cls.table_name} LIMIT ? OFFSET ?"
            results = cls.db.execute_query(query, (limit, offset))
            return [cls(**dict(row)) for row in results]
        except Exception as e:
            print(f"Error in find_all: {e}")
            return []
    
    @classmethod
    def find_where(cls, conditions: Dict[str, Any], limit: int = 100):
        """Find records matching conditions"""
        try:
            # Ensure table exists
            if not cls.db.table_exists(cls.table_name):
                return []
                
            where_clause = " AND ".join([f"{k} = ?" for k in conditions.keys()])
            query = f"SELECT * FROM {cls.table_name} WHERE {where_clause} LIMIT ?"
            params = tuple(conditions.values()) + (limit,)
            results = cls.db.execute_query(query, params)
            return [cls(**dict(row)) for row in results]
        except Exception as e:
            print(f"Error in find_where: {e}")
            return []
    
    @classmethod
    def count(cls, conditions: Dict[str, Any] = None):
        """Count records"""
        try:
            # Ensure table exists
            if not cls.db.table_exists(cls.table_name):
                return 0
                
            if conditions:
                where_clause = " AND ".join([f"{k} = ?" for k in conditions.keys()])
                query = f"SELECT COUNT(*) as count FROM {cls.table_name} WHERE {where_clause}"
                params = tuple(conditions.values())
            else:
                query = f"SELECT COUNT(*) as count FROM {cls.table_name}"
                params = ()
            
            result = cls.db.execute_query(query, params)
            return result[0]['count'] if result else 0
        except Exception as e:
            print(f"Error in count: {e}")
            return 0
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}


# ============================================================================
# USER MODEL
# ============================================================================

class User(BaseModel):
    """User model with authentication and RBAC"""
    table_name = "users"
    
    def __init__(self, user_id=None, username=None, email=None, password_hash=None,
                 role=None, full_name=None, department=None, is_active=True,
                 created_at=None, updated_at=None, last_login=None, **kwargs):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role if isinstance(role, str) else role.value if role else None
        self.full_name = full_name
        self.department = department
        self.is_active = is_active if isinstance(is_active, bool) else bool(is_active)
        self.created_at = created_at
        self.updated_at = updated_at
        self.last_login = last_login
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}${pwd_hash}"
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, pwd_hash = password_hash.split('$')
            return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
        except:
            return False
    
    @classmethod
    def create(cls, username: str, email: str, password: str, role: UserRole,
               full_name: str, department: str = None) -> 'User':
        """Create new user"""
        import uuid
        
        # Ensure table exists before inserting
        if not cls.db.table_exists(cls.table_name):
            print(f"⚠️  Warning: {cls.table_name} table does not exist. Creating tables first...")
            create_rbac_tables()
        
        user_id = str(uuid.uuid4())
        password_hash = cls.hash_password(password)
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        query = """
            INSERT INTO users (user_id, username, email, password_hash, role, 
                             full_name, department, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        cls.db.execute_insert(query, (
            user_id, username, email, password_hash, role.value,
            full_name, department, 1, timestamp, timestamp
        ))
        
        # Log the action
        try:
            AuditLog.create(
                user_id=user_id,
                action="USER_CREATED",
                resource_type="User",
                resource_id=user_id,
                details=f"User {username} created with role {role.value}"
            )
        except:
            pass  # Don't fail user creation if audit log fails
        
        return cls.find_by_id(user_id)
    
    @classmethod
    def authenticate(cls, username: str, password: str) -> Optional['User']:
        """Authenticate user by username and password"""
        try:
            # Ensure table exists
            if not cls.db.table_exists(cls.table_name):
                print(f"⚠️  Warning: {cls.table_name} table does not exist.")
                return None
                
            results = cls.db.execute_query(
                "SELECT * FROM users WHERE username = ? AND is_active = 1",
                (username,)
            )
            
            if not results:
                return None
            
            user = cls(**dict(results[0]))
            if cls.verify_password(password, user.password_hash):
                # Update last login
                cls.db.execute_update(
                    "UPDATE users SET last_login = ? WHERE user_id = ?",
                    (datetime.utcnow().isoformat() + "Z", user.user_id)
                )
                return user
            
            return None
        except Exception as e:
            print(f"Authentication error: {e}")
            return None
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has specific permission"""
        try:
            user_role = UserRole(self.role)
            return permission in ROLE_PERMISSIONS.get(user_role, [])
        except Exception as e:
            print(f"Permission check error: {e}")
            return False
    
    def has_any_permission(self, permissions: List[Permission]) -> bool:
        """Check if user has any of the specified permissions"""
        return any(self.has_permission(p) for p in permissions)
    
    def has_all_permissions(self, permissions: List[Permission]) -> bool:
        """Check if user has all specified permissions"""
        return all(self.has_permission(p) for p in permissions)
    
    def get_permissions(self) -> List[Permission]:
        """Get all permissions for user's role"""
        try:
            user_role = UserRole(self.role)
            return ROLE_PERMISSIONS.get(user_role, [])
        except:
            return []
    
    def update_role(self, new_role: UserRole, updated_by: str):
        """Update user role"""
        old_role = self.role
        query = "UPDATE users SET role = ?, updated_at = ? WHERE user_id = ?"
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        self.db.execute_update(query, (new_role.value, timestamp, self.user_id))
        
        # Log the action
        try:
            AuditLog.create(
                user_id=updated_by,
                action="ROLE_UPDATED",
                resource_type="User",
                resource_id=self.user_id,
                details=f"Role changed from {old_role} to {new_role.value}"
            )
        except:
            pass
        
        self.role = new_role.value
        self.updated_at = timestamp
    
    def deactivate(self, deactivated_by: str):
        """Deactivate user account"""
        query = "UPDATE users SET is_active = 0, updated_at = ? WHERE user_id = ?"
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        self.db.execute_update(query, (timestamp, self.user_id))
        
        try:
            AuditLog.create(
                user_id=deactivated_by,
                action="USER_DEACTIVATED",
                resource_type="User",
                resource_id=self.user_id,
                details=f"User {self.username} deactivated"
            )
        except:
            pass
        
        self.is_active = False


# ============================================================================
# INCIDENT MODEL
# ============================================================================

class Incident(BaseModel):
    """Incident model"""
    table_name = "incident_logs"
    
    def __init__(self, id=None, incident_json=None, source_type=None, 
                 status=None, **kwargs):
        self.id = id
        self.incident_json = incident_json
        self.source_type = source_type
        self.status = status
    
    @classmethod
    def create(cls, incident_data: Dict, source_type: str, user_id: str):
        """Create new incident"""
        import uuid
        incident_id = str(uuid.uuid4())
        
        query = """
            INSERT INTO incident_logs (id, incident_json, source_type, status)
            VALUES (?, ?, ?, ?)
        """
        
        cls.db.execute_insert(query, (
            incident_id,
            json.dumps(incident_data),
            source_type,
            "new"
        ))
        
        try:
            AuditLog.create(
                user_id=user_id,
                action="INCIDENT_CREATED",
                resource_type="Incident",
                resource_id=incident_id,
                details=f"Incident created from {source_type}"
            )
        except:
            pass
        
        return cls.find_by_id(incident_id)
    
    @classmethod
    def find_by_status(cls, status: str, limit: int = 100):
        """Find incidents by status"""
        return cls.find_where({"status": status}, limit)
    
    def update_status(self, new_status: str, user_id: str):
        """Update incident status"""
        old_status = self.status
        query = "UPDATE incident_logs SET status = ? WHERE id = ?"
        
        self.db.execute_update(query, (new_status, self.id))
        
        try:
            AuditLog.create(
                user_id=user_id,
                action="INCIDENT_STATUS_UPDATED",
                resource_type="Incident",
                resource_id=self.id,
                details=f"Status changed from {old_status} to {new_status}"
            )
        except:
            pass
        
        self.status = new_status
    
    def get_data(self) -> Dict:
        """Get incident data as dictionary"""
        try:
            return json.loads(self.incident_json) if self.incident_json else {}
        except:
            return {}


# ============================================================================
# ALERT MODEL
# ============================================================================

class Alert(BaseModel):
    """Alert model"""
    table_name = "azure_alerts"
    
    def __init__(self, alert_id=None, alert_name=None, alert_type=None,
                 severity=None, environment=None, alert_status=None,
                 fired_time=None, resolved_time=None, alert_payload=None,
                 email_body=None, resource_id=None, subscription_id=None,
                 created_at=None, **kwargs):
        self.alert_id = alert_id
        self.alert_name = alert_name
        self.alert_type = alert_type
        self.severity = severity
        self.environment = environment
        self.alert_status = alert_status
        self.fired_time = fired_time
        self.resolved_time = resolved_time
        self.alert_payload = alert_payload
        self.email_body = email_body
        self.resource_id = resource_id
        self.subscription_id = subscription_id
        self.created_at = created_at
    
    @classmethod
    def find_by_severity(cls, severity: str, limit: int = 100):
        """Find alerts by severity"""
        return cls.find_where({"severity": severity}, limit)
    
    @classmethod
    def find_active_alerts(cls, limit: int = 100):
        """Find all active (fired) alerts"""
        try:
            if not cls.db.table_exists(cls.table_name):
                return []
                
            query = f"SELECT * FROM {cls.table_name} WHERE alert_status = 'Fired' LIMIT ?"
            results = cls.db.execute_query(query, (limit,))
            return [cls(**dict(row)) for row in results]
        except:
            return []
    
    @classmethod
    def find_by_environment(cls, environment: str, limit: int = 100):
        """Find alerts by environment"""
        return cls.find_where({"environment": environment}, limit)
    
    def acknowledge(self, user_id: str):
        """Acknowledge alert"""
        query = "UPDATE azure_alerts SET alert_status = 'Acknowledged' WHERE alert_id = ?"
        self.db.execute_update(query, (self.alert_id,))
        
        try:
            AuditLog.create(
                user_id=user_id,
                action="ALERT_ACKNOWLEDGED",
                resource_type="Alert",
                resource_id=self.alert_id,
                details=f"Alert {self.alert_name} acknowledged"
            )
        except:
            pass
        
        self.alert_status = "Acknowledged"
    
    def resolve(self, user_id: str):
        """Resolve alert"""
        resolved_time = datetime.utcnow().isoformat() + "Z"
        query = """
            UPDATE azure_alerts 
            SET alert_status = 'Resolved', resolved_time = ? 
            WHERE alert_id = ?
        """
        self.db.execute_update(query, (resolved_time, self.alert_id))
        
        try:
            AuditLog.create(
                user_id=user_id,
                action="ALERT_RESOLVED",
                resource_type="Alert",
                resource_id=self.alert_id,
                details=f"Alert {self.alert_name} resolved"
            )
        except:
            pass
        
        self.alert_status = "Resolved"
        self.resolved_time = resolved_time


# ============================================================================
# KNOWLEDGE BASE MODEL
# ============================================================================

class KnowledgeBase(BaseModel):
    """Knowledge base model"""
    table_name = "incident_knowledge_base"
    
    def __init__(self, incident_id=None, cloud_provider=None, severity=None,
                 cause=None, description=None, impact=None, remediation=None,
                 root_cause=None, prevention=None, affected_services=None,
                 business_impact=None, estimated_recovery_time=None,
                 actual_recovery_time=None, start_time=None, end_time=None,
                 detection_method=None, incident_commander=None, status=None,
                 created_at=None, **kwargs):
        self.incident_id = incident_id
        self.cloud_provider = cloud_provider
        self.severity = severity
        self.cause = cause
        self.description = description
        self.impact = impact
        self.remediation = remediation
        self.root_cause = root_cause
        self.prevention = prevention
        self.affected_services = affected_services
        self.business_impact = business_impact
        self.estimated_recovery_time = estimated_recovery_time
        self.actual_recovery_time = actual_recovery_time
        self.start_time = start_time
        self.end_time = end_time
        self.detection_method = detection_method
        self.incident_commander = incident_commander
        self.status = status
        self.created_at = created_at
    
    @classmethod
    def search_by_cause(cls, search_term: str, limit: int = 10):
        """Search knowledge base by cause"""
        try:
            if not cls.db.table_exists(cls.table_name):
                return []
                
            query = f"""
                SELECT * FROM {cls.table_name} 
                WHERE cause LIKE ? OR description LIKE ?
                LIMIT ?
            """
            search_pattern = f"%{search_term}%"
            results = cls.db.execute_query(query, (search_pattern, search_pattern, limit))
            return [cls(**dict(row)) for row in results]
        except:
            return []
    
    @classmethod
    def find_by_cloud_provider(cls, cloud_provider: str, limit: int = 100):
        """Find incidents by cloud provider"""
        return cls.find_where({"cloud_provider": cloud_provider}, limit)
    
    @classmethod
    def find_similar_incidents(cls, severity: str, cloud_provider: str, limit: int = 5):
        """Find similar incidents for recommendation"""
        return cls.find_where({
            "severity": severity,
            "cloud_provider": cloud_provider
        }, limit)
    
    def get_affected_services_list(self) -> List[str]:
        """Get affected services as list"""
        try:
            return json.loads(self.affected_services) if self.affected_services else []
        except:
            return []


# ============================================================================
# AUDIT LOG MODEL
# ============================================================================

class AuditLog(BaseModel):
    """Audit log model for tracking all system actions"""
    table_name = "audit_logs"
    
    def __init__(self, log_id=None, user_id=None, action=None, resource_type=None,
                 resource_id=None, details=None, ip_address=None, user_agent=None,
                 created_at=None, **kwargs):
        self.log_id = log_id
        self.user_id = user_id
        self.action = action
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.details = details
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.created_at = created_at
    
    @classmethod
    def create(cls, user_id: str, action: str, resource_type: str,
               resource_id: str, details: str, ip_address: str = None,
               user_agent: str = None):
        """Create audit log entry"""
        import uuid
        
        # Ensure table exists before inserting
        if not cls.db.table_exists(cls.table_name):
            create_rbac_tables()
        
        log_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        query = """
            INSERT INTO audit_logs (log_id, user_id, action, resource_type,
                                  resource_id, details, ip_address, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        cls.db.execute_insert(query, (
            log_id, user_id, action, resource_type, resource_id,
            details, ip_address, user_agent, timestamp
        ))
    
    @classmethod
    def find_by_user(cls, user_id: str, limit: int = 100):
        """Find audit logs for specific user"""
        return cls.find_where({"user_id": user_id}, limit)
    
    @classmethod
    def find_by_resource(cls, resource_type: str, resource_id: str, limit: int = 100):
        """Find audit logs for specific resource"""
        try:
            if not cls.db.table_exists(cls.table_name):
                return []
                
            query = f"""
                SELECT * FROM {cls.table_name} 
                WHERE resource_type = ? AND resource_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            """
            results = cls.db.execute_query(query, (resource_type, resource_id, limit))
            return [cls(**dict(row)) for row in results]
        except:
            return []


# ============================================================================
# RBAC DECORATOR
# ============================================================================

def require_permission(*permissions: Permission):
    """Decorator to check user permissions"""
    def decorator(func):
        def wrapper(user: User, *args, **kwargs):
            if not user or not user.is_active:
                raise PermissionError("User is not active")
            
            if not user.has_all_permissions(list(permissions)):
                missing = [p.value for p in permissions if not user.has_permission(p)]
                raise PermissionError(f"Missing permissions: {', '.join(missing)}")
            
            return func(user, *args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# DATABASE SCHEMA CREATION
# ============================================================================

def create_rbac_tables(recreate=False):
    """Create all RBAC-related tables
    
    Args:
        recreate (bool): If True, drop existing tables and recreate them
    """
    db = DatabaseManager()
    
    print("\n🔧 Setting up RBAC tables...")
    
    with db.get_connection() as conn:
        cursor = conn.cursor()
        
        if recreate:
            print("🗑️  Dropping existing RBAC tables...")
            cursor.execute("DROP TABLE IF EXISTS audit_logs")
            cursor.execute("DROP TABLE IF EXISTS users")
            print("✓ Existing RBAC tables dropped")
        
        # Users table
        print("📝 Creating users table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT NOT NULL,
            department TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
        """)
        
        # Audit logs table
        print("📝 Creating audit_logs table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
        """)
        
        # Create indexes
        print("📝 Creating indexes...")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type, resource_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)")
        
        print("✓ RBAC tables created successfully")


def seed_default_users(force=False):
    """Create default users for testing
    
    Args:
        force (bool): If True, delete existing users before seeding
    """
    db = DatabaseManager()
    
    # Ensure tables exist first
    if not db.table_exists("users"):
        print("⚠️  Users table does not exist. Creating RBAC tables first...")
        create_rbac_tables()
    
    try:
        if force:
            print("🗑️  Clearing existing users...")
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users")
            print("✓ Existing users cleared")
        else:
            # Check if users already exist
            existing_users = User.find_all(limit=1)
            if existing_users:
                print("⚠️  Users already exist. Use --force to recreate.")
                print(f"   Found {User.count()} existing users.")
                return
        
        print("\n📝 Creating default users...")
        
        # Admin
        User.create(
            username="admin",
            email="admin@company.com",
            password="Admin@123",
            role=UserRole.ADMIN,
            full_name="System Administrator",
            department="IT Operations"
        )
        
        # SRE Lead
        User.create(
            username="sre_lead",
            email="sre.lead@company.com",
            password="Sre@123",
            role=UserRole.SRE_LEAD,
            full_name="SRE Team Lead",
            department="Site Reliability Engineering"
        )
        
        # SRE Engineer
        User.create(
            username="sre_engineer",
            email="sre.engineer@company.com",
            password="Sre@123",
            role=UserRole.SRE_ENGINEER,
            full_name="SRE Engineer",
            department="Site Reliability Engineering"
        )
        
        # Developer
        User.create(
            username="developer",
            email="developer@company.com",
            password="Dev@123",
            role=UserRole.DEVELOPER,
            full_name="Software Developer",
            department="Engineering"
        )
        
        # Viewer
        User.create(
            username="viewer",
            email="viewer@company.com",
            password="View@123",
            role=UserRole.VIEWER,
            full_name="Read-Only User",
            department="Business"
        )
        
        print("✓ Default users created successfully")
        print("\n📝 Default User Credentials:")
        print("=" * 60)
        print("Username         | Password   | Role")
        print("-" * 60)
        print("admin            | Admin@123  | Administrator (Full Access)")
        print("sre_lead         | Sre@123    | SRE Lead")
        print("sre_engineer     | Sre@123    | SRE Engineer")
        print("developer        | Dev@123    | Developer")
        print("viewer           | View@123   | Viewer (Read-Only)")
        print("=" * 60)
        
    except Exception as e:
        print(f"⚠️  Error seeding users: {e}")
        import traceback
        traceback.print_exc()


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

def demo_rbac_usage():
    """Demonstrate RBAC system usage"""
    
    print("\n" + "=" * 70)
    print("🔐 RBAC SYSTEM DEMONSTRATION (5 ROLES)")
    print("=" * 70)
    
    # 1. User Authentication
    print("\n1️⃣  User Authentication:")
    print("-" * 70)
    user = User.authenticate("sre_engineer", "Sre@123")
    if user:
        print(f"✓ Authenticated: {user.full_name} ({user.role})")
        print(f"  Email: {user.email}")
        print(f"  Department: {user.department}")
        print(f"  Last Login: {user.last_login}")
    else:
        print("✗ Authentication failed - No users found in database")
        print("⚠️  Please make sure you ran seed_default_users() first")
        return  # Exit early
    
    # 2. Check Permissions
    print("\n2️⃣  Permission Checks:")
    print("-" * 70)
    permissions_to_check = [
        Permission.VIEW_INCIDENTS,
        Permission.DELETE_INCIDENTS,
        Permission.CREATE_USERS,
        Permission.RESOLVE_ALERTS
    ]
    
    for perm in permissions_to_check:
        has_perm = user.has_permission(perm)
        status = "✓" if has_perm else "✗"
        print(f"{status} {perm.value}: {has_perm}")
    
    # 3. List all permissions for role
    print(f"\n3️⃣  All Permissions for {user.role}:")
    print("-" * 70)
    all_perms = user.get_permissions()
    print(f"Total permissions: {len(all_perms)}")
    for perm in all_perms:
        print(f"  • {perm.value}")
    
    # 4. Query Incidents (with permission check)
    print("\n4️⃣  Query Incidents:")
    print("-" * 70)
    if user.has_permission(Permission.VIEW_INCIDENTS):
        incidents = Incident.find_all(limit=5)
        print(f"✓ Permission granted - Found {len(incidents)} incidents")
        if incidents:
            for inc in incidents[:3]:
                print(f"  • {inc.id} - Status: {inc.status}")
        else:
            print("  (No incidents in database)")
    else:
        print("✗ Permission denied")
    
    # 5. Query Alerts
    print("\n5️⃣  Query Active Alerts:")
    print("-" * 70)
    if user.has_permission(Permission.VIEW_ALERTS):
        alerts = Alert.find_active_alerts(limit=5)
        print(f"✓ Permission granted - Found {len(alerts)} active alerts")
        if alerts:
            for alert in alerts[:3]:
                print(f"  • {alert.alert_name} - {alert.severity} - {alert.environment}")
        else:
            print("  (No active alerts in database)")
    else:
        print("✗ Permission denied")
    
    # 6. Search Knowledge Base
    print("\n6️⃣  Search Knowledge Base:")
    print("-" * 70)
    if user.has_permission(Permission.VIEW_KNOWLEDGE_BASE):
        kb_results = KnowledgeBase.search_by_cause("database", limit=3)
        print(f"✓ Permission granted - Found {len(kb_results)} knowledge base entries")
        if kb_results:
            for kb in kb_results:
                print(f"  • {kb.cloud_provider} - {kb.severity}: {kb.cause[:60]}...")
        else:
            print("  (No knowledge base entries matching 'database')")
    else:
        print("✗ Permission denied")
    
    # 7. View Audit Logs (if permitted)
    print("\n7️⃣  Audit Log Activity:")
    print("-" * 70)
    if user.has_permission(Permission.VIEW_AUDIT_LOGS):
        logs = AuditLog.find_by_user(user.user_id, limit=5)
        print(f"✓ Permission granted - Found {len(logs)} audit log entries")
        if logs:
            for log in logs[:3]:
                print(f"  • {log.action} on {log.resource_type} at {log.created_at}")
    else:
        print("✗ No permission to view audit logs (SRE Engineers cannot view audit logs)")
    
    # 8. Try restricted operation
    print("\n8️⃣  Attempting Restricted Operation (Delete User):")
    print("-" * 70)
    try:
        @require_permission(Permission.DELETE_USERS)
        def delete_user_example(current_user: User, target_user_id: str):
            return f"Deleting user {target_user_id}"
        
        result = delete_user_example(user, "some-user-id")
        print(f"✓ {result}")
    except PermissionError as e:
        print(f"✗ Permission Denied: {e}")
    
    # 9. Show role hierarchy
    print("\n9️⃣  Role Hierarchy & Permission Summary:")
    print("-" * 70)
    for role in UserRole:
        perms = ROLE_PERMISSIONS.get(role, [])
        print(f"\n{role.value.upper()}: {len(perms)} permissions")
        print(f"  Key capabilities: ", end="")
        if role == UserRole.ADMIN:
            print("Full system access - all operations")
        elif role == UserRole.SRE_LEAD:
            print("Incident management, knowledge base, user viewing, audits")
        elif role == UserRole.SRE_ENGINEER:
            print("Incident resolution, alert management, knowledge updates")
        elif role == UserRole.DEVELOPER:
            print("View and create incidents, acknowledge alerts, view KB")
        elif role == UserRole.VIEWER:
            print("Read-only access to incidents, alerts, knowledge base, analytics")
    
    print("\n" + "=" * 70)
    print("✅ RBAC Demonstration Complete!")
    print("=" * 70)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🚀 RBAC System Setup - Cloud Incident Management")
    print("=" * 70)
    
    # Check for command line arguments
    recreate = "--recreate" in sys.argv or "-r" in sys.argv
    force = "--force" in sys.argv or "-f" in sys.argv
    
    if recreate:
        print("\n⚠️  RECREATE MODE: Tables will be dropped and recreated")
        print("⚠️  All existing data will be lost!")
        confirm = input("\nContinue? (yes/no): ")
        if confirm.lower() != "yes":
            print("❌ Operation cancelled")
            sys.exit(0)
    
    # Create tables first (always)
    create_rbac_tables(recreate=recreate)
    
    # Seed default users
    seed_default_users(force=force or recreate)
    
    # Run demonstration
    demo_rbac_usage()
    
    print("\n" + "=" * 70)
    print("💡 Usage Examples:")
    print("=" * 70)
    print("  python rbac_system.py              # Normal mode")
    print("  python rbac_system.py --recreate   # Drop and recreate tables")
    print("  python rbac_system.py --force      # Reseed users")
    print("  python rbac_system.py -r -f        # Both modes")
    print("=" * 70)
