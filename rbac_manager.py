# rbac_manager.py
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import json

class RBACManager:
    """Comprehensive RBAC management system"""
    
    def __init__(self, db_path='incident_management.db'):
        self.db_path = db_path
        self.conn = None
        
    def connect(self):
        """Establish database connection"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    # ==================== User Management ====================
    
    def create_user(self, username: str, email: str, password: str, 
                   full_name: str, department: str = None) -> Tuple[bool, str, int]:
        """
        Create a new user with hashed password
        Returns: (success, message, user_id)
        """
        try:
            cursor = self.conn.cursor()
            
            # Hash password with salt
            salt = secrets.token_hex(16)
            password_hash = self._hash_password(password, salt)
            
            cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, department)
            VALUES (?, ?, ?, ?, ?)
            ''', (username, email, password_hash, full_name, department))
            
            user_id = cursor.lastrowid
            self.conn.commit()
            
            # Log the action
            self._log_audit(None, 'CREATE_USER', 'users', user_id, 
                          {'username': username, 'email': email})
            
            return True, f"User {username} created successfully", user_id
            
        except sqlite3.IntegrityError as e:
            return False, f"User already exists: {str(e)}", -1
        except Exception as e:
            return False, f"Error creating user: {str(e)}", -1
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[Dict]]:
        """
        Authenticate user and return user info if successful
        Returns: (success, user_info_dict)
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
        SELECT user_id, username, email, password_hash, full_name, 
               department, is_active
        FROM users
        WHERE username = ? AND is_active = 1
        ''', (username,))
        
        user = cursor.fetchone()
        
        if not user:
            return False, None
        
        # Verify password
        stored_hash = user['password_hash']
        if not self._verify_password(password, stored_hash):
            return False, None
        
        # Update last login
        cursor.execute('''
        UPDATE users SET last_login = CURRENT_TIMESTAMP
        WHERE user_id = ?
        ''', (user['user_id'],))
        self.conn.commit()
        
        # Log successful login
        self._log_audit(user['user_id'], 'LOGIN', 'auth', None, 
                       {'username': username})
        
        user_info = {
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email'],
            'full_name': user['full_name'],
            'department': user['department']
        }
        
        return True, user_info
    
    def assign_role_to_user(self, user_id: int, role_name: str, 
                           assigned_by: int, expires_at: str = None) -> Tuple[bool, str]:
        """
        Assign a role to a user
        expires_at format: 'YYYY-MM-DD HH:MM:SS' or None for permanent
        """
        try:
            cursor = self.conn.cursor()
            
            # Get role_id
            cursor.execute('SELECT role_id FROM roles WHERE role_name = ?', (role_name,))
            role = cursor.fetchone()
            
            if not role:
                return False, f"Role '{role_name}' not found"
            
            role_id = role['role_id']
            
            # Assign role
            cursor.execute('''
            INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by, expires_at)
            VALUES (?, ?, ?, ?)
            ''', (user_id, role_id, assigned_by, expires_at))
            
            self.conn.commit()
            
            # Log the action
            self._log_audit(assigned_by, 'ASSIGN_ROLE', 'user_roles', user_id,
                          {'role': role_name, 'expires_at': expires_at})
            
            return True, f"Role '{role_name}' assigned to user successfully"
            
        except Exception as e:
            return False, f"Error assigning role: {str(e)}"
    
    def revoke_role_from_user(self, user_id: int, role_name: str, 
                             revoked_by: int) -> Tuple[bool, str]:
        """Revoke a role from a user"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('SELECT role_id FROM roles WHERE role_name = ?', (role_name,))
            role = cursor.fetchone()
            
            if not role:
                return False, f"Role '{role_name}' not found"
            
            role_id = role['role_id']
            
            cursor.execute('''
            DELETE FROM user_roles
            WHERE user_id = ? AND role_id = ?
            ''', (user_id, role_id))
            
            self.conn.commit()
            
            # Log the action
            self._log_audit(revoked_by, 'REVOKE_ROLE', 'user_roles', user_id,
                          {'role': role_name})
            
            return True, f"Role '{role_name}' revoked from user successfully"
            
        except Exception as e:
            return False, f"Error revoking role: {str(e)}"
    
    def get_user_roles(self, user_id: int) -> List[str]:
        """Get all active roles for a user"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
        SELECT r.role_name
        FROM roles r
        JOIN user_roles ur ON r.role_id = ur.role_id
        WHERE ur.user_id = ?
          AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
        ''', (user_id,))
        
        return [row['role_name'] for row in cursor.fetchall()]
    
    # ==================== Permission Checking ====================
    
    def has_permission(self, user_id: int, permission_name: str) -> bool:
        """
        Check if user has a specific permission through their roles
        This is the CORE authorization function
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
        SELECT COUNT(*) as count
        FROM permissions p
        JOIN role_permissions rp ON p.permission_id = rp.permission_id
        JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ?
          AND p.permission_name = ?
          AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
        ''', (user_id, permission_name))
        
        result = cursor.fetchone()
        return result['count'] > 0
    
    def has_any_permission(self, user_id: int, permission_names: List[str]) -> bool:
        """Check if user has ANY of the specified permissions"""
        for perm in permission_names:
            if self.has_permission(user_id, perm):
                return True
        return False
    
    def has_all_permissions(self, user_id: int, permission_names: List[str]) -> bool:
        """Check if user has ALL of the specified permissions"""
        for perm in permission_names:
            if not self.has_permission(user_id, perm):
                return False
        return True
    
    def get_user_permissions(self, user_id: int) -> List[Dict]:
        """Get all permissions for a user with details"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
        SELECT DISTINCT p.permission_name, p.resource, p.action, p.description
        FROM permissions p
        JOIN role_permissions rp ON p.permission_id = rp.permission_id
        JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ?
          AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
        ORDER BY p.resource, p.action
        ''', (user_id,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def can_access_incident(self, user_id: int, incident_id: int) -> Tuple[bool, str]:
        """
        Check if user can access a specific incident
        Returns: (can_access, access_level)
        access_level: 'view', 'edit', 'manage', or 'none'
        """
        # Check basic view permission
        if not self.has_permission(user_id, 'view_incidents'):
            return False, 'none'
        
        # Determine access level
        if self.has_permission(user_id, 'delete_incidents'):
            return True, 'manage'
        elif self.has_permission(user_id, 'update_incidents'):
            return True, 'edit'
        else:
            return True, 'view'
    
    # ==================== Role Management ====================
    
    def create_custom_role(self, role_name: str, description: str, 
                          priority_level: int, permission_names: List[str],
                          created_by: int) -> Tuple[bool, str]:
        """Create a custom role with specific permissions"""
        try:
            cursor = self.conn.cursor()
            
            # Create role
            cursor.execute('''
            INSERT INTO roles (role_name, description, priority_level)
            VALUES (?, ?, ?)
            ''', (role_name, description, priority_level))
            
            role_id = cursor.lastrowid
            
            # Assign permissions
            for perm_name in permission_names:
                cursor.execute('''
                SELECT permission_id FROM permissions WHERE permission_name = ?
                ''', (perm_name,))
                perm = cursor.fetchone()
                
                if perm:
                    cursor.execute('''
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (?, ?)
                    ''', (role_id, perm['permission_id']))
            
            self.conn.commit()
            
            # Log the action
            self._log_audit(created_by, 'CREATE_ROLE', 'roles', role_id,
                          {'role_name': role_name, 'permissions': permission_names})
            
            return True, f"Role '{role_name}' created successfully"
            
        except sqlite3.IntegrityError:
            return False, f"Role '{role_name}' already exists"
        except Exception as e:
            return False, f"Error creating role: {str(e)}"
    
    def get_role_permissions(self, role_name: str) -> List[str]:
        """Get all permissions for a role"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
        SELECT p.permission_name
        FROM permissions p
        JOIN role_permissions rp ON p.permission_id = rp.permission_id
        JOIN roles r ON rp.role_id = r.role_id
        WHERE r.role_name = ?
        ''', (role_name,))
        
        return [row['permission_name'] for row in cursor.fetchall()]
    
    # ==================== Audit Logging ====================
    
    def _log_audit(self, user_id: Optional[int], action: str, resource: str,
                  resource_id: Optional[int], details: Dict, ip_address: str = None):
        """Log an action to audit trail"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            INSERT INTO audit_logs (user_id, action, resource, resource_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, action, resource, resource_id, json.dumps(details), ip_address))
            
            self.conn.commit()
        except Exception as e:
            print(f"Audit logging error: {e}")
    
    def get_audit_logs(self, user_id: int = None, resource: str = None,
                      start_date: str = None, limit: int = 100) -> List[Dict]:
        """Retrieve audit logs with filters"""
        cursor = self.conn.cursor()
        
        query = '''
        SELECT al.*, u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.user_id
        WHERE 1=1
        '''
        params = []
        
        if user_id:
            query += ' AND al.user_id = ?'
            params.append(user_id)
        
        if resource:
            query += ' AND al.resource = ?'
            params.append(resource)
        
        if start_date:
            query += ' AND al.timestamp >= ?'
            params.append(start_date)
        
        query += ' ORDER BY al.timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== Utility Functions ====================
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using SHA-256"""
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest() + f":{salt}"
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            hash_part, salt = password_hash.split(':')
            return self._hash_password(password, salt) == password_hash
        except:
            return False
    
    def get_user_info(self, user_id: int) -> Optional[Dict]:
        """Get detailed user information"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
        SELECT user_id, username, email, full_name, department, 
               is_active, created_at, last_login
        FROM users
        WHERE user_id = ?
        ''', (user_id,))
        
        user = cursor.fetchone()
        return dict(user) if user else None


# Decorator for permission checking
def requires_permission(permission_name: str):
    """Decorator to check permissions before executing function"""
    def decorator(func):
        def wrapper(self, user_id: int, *args, **kwargs):
            if not self.rbac.has_permission(user_id, permission_name):
                return {
                    'success': False,
                    'error': f'Permission denied: {permission_name} required',
                    'error_code': 'PERMISSION_DENIED'
                }
            return func(self, user_id, *args, **kwargs)
        return wrapper
    return decorator
