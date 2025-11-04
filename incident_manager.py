# incident_manager.py
import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from rbac_manager import RBACManager, requires_permission

class IncidentManager:
    """Incident management system with RBAC integration"""
    
    def __init__(self, db_path='incident_management.db'):
        self.db_path = db_path
        self.conn = None
        self.rbac = RBACManager(db_path)
        
    def connect(self):
        """Establish database connection"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.rbac.connect()
        return self.conn
    
    def close(self):
        """Close database connections"""
        if self.conn:
            self.conn.close()
        self.rbac.close()
    
    # ==================== Incident Operations ====================
    
    @requires_permission('create_incidents')
    def create_incident(self, user_id: int, title: str, description: str,
                       severity: str, affected_service: str, 
                       log_data: Optional[str] = None) -> Dict:
        """Create a new incident (requires create_incidents permission)"""
        try:
            cursor = self.conn.cursor()
            
            # Generate unique incident code
            incident_code = self._generate_incident_code(severity)
            
            cursor.execute('''
            INSERT INTO incidents (incident_code, title, description, severity,
                                 affected_service, created_by, status)
            VALUES (?, ?, ?, ?, ?, ?, 'open')
            ''', (incident_code, title, description, severity, affected_service, user_id))
            
            incident_id = cursor.lastrowid
            
            # Add log data if provided
            if log_data:
                cursor.execute('''
                INSERT INTO incident_logs (incident_id, log_data, log_type)
                VALUES (?, ?, 'system')
                ''', (incident_id, log_data))
            
            self.conn.commit()
            
            # Audit log
            self.rbac._log_audit(user_id, 'CREATE_INCIDENT', 'incidents', incident_id,
                               {'incident_code': incident_code, 'severity': severity})
            
            return {
                'success': True,
                'incident_id': incident_id,
                'incident_code': incident_code,
                'message': f'Incident {incident_code} created successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error creating incident: {str(e)}'
            }
    
    def view_incident(self, user_id: int, incident_id: int) -> Dict:
        """View incident details (checks view_incidents permission)"""
        # Check permission
        can_access, access_level = self.rbac.can_access_incident(user_id, incident_id)
        
        if not can_access:
            return {
                'success': False,
                'error': 'Permission denied: view_incidents required',
                'error_code': 'PERMISSION_DENIED'
            }
        
        cursor = self.conn.cursor()
        
        cursor.execute('''
        SELECT i.*, 
               u1.username as created_by_name,
               u2.username as assigned_to_name
        FROM incidents i
        LEFT JOIN users u1 ON i.created_by = u1.user_id
        LEFT JOIN users u2 ON i.assigned_to = u2.user_id
        WHERE i.incident_id = ?
        ''', (incident_id,))
        
        incident = cursor.fetchone()
        
        if not incident:
            return {
                'success': False,
                'error': 'Incident not found'
            }
        
        # Get incident logs if user has permission
        logs = []
        if self.rbac.has_permission(user_id, 'view_logs'):
            cursor.execute('''
            SELECT log_id, log_data, log_type, timestamp
            FROM incident_logs
            WHERE incident_id = ?
            ORDER BY timestamp DESC
            ''', (incident_id,))
            logs = [dict(row) for row in cursor.fetchall()]
        
        # Get AI recommendations if user has permission
        recommendations = []
        if self.rbac.has_permission(user_id, 'view_ai_recommendations'):
            cursor.execute('''
            SELECT recommendation_id, recommendation_type, recommendation_data,
                   confidence_score, execution_status, created_at
            FROM ai_recommendations
            WHERE incident_id = ?
            ORDER BY created_at DESC
            ''', (incident_id,))
            recommendations = [dict(row) for row in cursor.fetchall()]
        
        return {
            'success': True,
            'incident': dict(incident),
            'logs': logs,
            'ai_recommendations': recommendations,
            'access_level': access_level
        }
    
    @requires_permission('update_incidents')
    def update_incident(self, user_id: int, incident_id: int, **updates) -> Dict:
        """Update incident fields (requires update_incidents permission)"""
        try:
            allowed_fields = ['title', 'description', 'severity', 'status', 
                            'affected_service']
            
            update_parts = []
            values = []
            
            for field, value in updates.items():
                if field in allowed_fields:
                    update_parts.append(f"{field} = ?")
                    values.append(value)
            
            if not update_parts:
                return {
                    'success': False,
                    'error': 'No valid fields to update'
                }
            
            values.append(incident_id)
            
            cursor = self.conn.cursor()
            query = f"UPDATE incidents SET {', '.join(update_parts)}, updated_at = CURRENT_TIMESTAMP WHERE incident_id = ?"
            
            cursor.execute(query, values)
            self.conn.commit()
            
            # Audit log
            self.rbac._log_audit(user_id, 'UPDATE_INCIDENT', 'incidents', incident_id,
                               {'updates': updates})
            
            return {
                'success': True,
                'message': 'Incident updated successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error updating incident: {str(e)}'
            }
    
    @requires_permission('assign_incidents')
    def assign_incident(self, user_id: int, incident_id: int, 
                       assign_to_user_id: int) -> Dict:
        """Assign incident to a user (requires assign_incidents permission)"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            UPDATE incidents
            SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
            ''', (assign_to_user_id, incident_id))
            
            self.conn.commit()
            
            # Audit log
            self.rbac._log_audit(user_id, 'ASSIGN_INCIDENT', 'incidents', incident_id,
                               {'assigned_to': assign_to_user_id})
            
            return {
                'success': True,
                'message': 'Incident assigned successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error assigning incident: {str(e)}'
            }
    
    @requires_permission('resolve_incidents')
    def resolve_incident(self, user_id: int, incident_id: int, 
                        resolution_notes: str) -> Dict:
        """Resolve an incident (requires resolve_incidents permission)"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            UPDATE incidents
            SET status = 'resolved', 
                resolved_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
            ''', (incident_id,))
            
            # Add resolution notes as log
            cursor.execute('''
            INSERT INTO incident_logs (incident_id, log_data, log_type)
            VALUES (?, ?, 'resolution')
            ''', (incident_id, json.dumps({'notes': resolution_notes, 'resolved_by': user_id})))
            
            self.conn.commit()
            
            # Audit log
            self.rbac._log_audit(user_id, 'RESOLVE_INCIDENT', 'incidents', incident_id,
                               {'resolution_notes': resolution_notes})
            
            return {
                'success': True,
                'message': 'Incident resolved successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error resolving incident: {str(e)}'
            }
    
    def list_incidents(self, user_id: int, filters: Dict = None) -> Dict:
        """List incidents based on user permissions and filters"""
        # Check basic view permission
        if not self.rbac.has_permission(user_id, 'view_incidents'):
            return {
                'success': False,
                'error': 'Permission denied: view_incidents required',
                'error_code': 'PERMISSION_DENIED'
            }
        
        cursor = self.conn.cursor()
        
        query = '''
        SELECT i.incident_id, i.incident_code, i.title, i.severity, i.status,
               i.affected_service, i.created_at, i.updated_at,
               u1.username as created_by_name,
               u2.username as assigned_to_name
        FROM incidents i
        LEFT JOIN users u1 ON i.created_by = u1.user_id
        LEFT JOIN users u2 ON i.assigned_to = u2.user_id
        WHERE 1=1
        '''
        params = []
        
        # Apply filters
        if filters:
            if filters.get('severity'):
                query += ' AND i.severity = ?'
                params.append(filters['severity'])
            
            if filters.get('status'):
                query += ' AND i.status = ?'
                params.append(filters['status'])
            
            if filters.get('assigned_to_me'):
                query += ' AND i.assigned_to = ?'
                params.append(user_id)
        
        query += ' ORDER BY i.created_at DESC LIMIT 100'
        
        cursor.execute(query, params)
        incidents = [dict(row) for row in cursor.fetchall()]
        
        return {
            'success': True,
            'incidents': incidents,
            'count': len(incidents)
        }
    
    # ==================== AI Integration ====================
    
    @requires_permission('execute_ai_recommendations')
    def add_ai_recommendation(self, user_id: int, incident_id: int,
                             recommendation_type: str, recommendation_data: Dict,
                             confidence_score: float) -> Dict:
        """Add AI-generated recommendation to incident"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            INSERT INTO ai_recommendations 
            (incident_id, recommendation_type, recommendation_data, 
             confidence_score, execution_status)
            VALUES (?, ?, ?, ?, 'pending')
            ''', (incident_id, recommendation_type, json.dumps(recommendation_data), 
                  confidence_score))
            
            rec_id = cursor.lastrowid
            self.conn.commit()
            
            return {
                'success': True,
                'recommendation_id': rec_id,
                'message': 'AI recommendation added successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error adding recommendation: {str(e)}'
            }
    
    @requires_permission('approve_ai_actions')
    def approve_ai_recommendation(self, user_id: int, recommendation_id: int) -> Dict:
        """Approve AI recommendation for execution"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            UPDATE ai_recommendations
            SET execution_status = 'approved',
                executed_by = ?,
                executed_at = CURRENT_TIMESTAMP
            WHERE recommendation_id = ?
            ''', (user_id, recommendation_id))
            
            self.conn.commit()
            
            # Audit log
            self.rbac._log_audit(user_id, 'APPROVE_AI_RECOMMENDATION', 
                               'ai_recommendations', recommendation_id, {})
            
            return {
                'success': True,
                'message': 'AI recommendation approved successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error approving recommendation: {str(e)}'
            }
    
    # ==================== Utility Functions ====================
    
    def _generate_incident_code(self, severity: str) -> str:
        """Generate unique incident code"""
        prefix_map = {
            'critical': 'CRIT',
            'high': 'HIGH',
            'medium': 'MED',
            'low': 'LOW'
        }
        
        prefix = prefix_map.get(severity.lower(), 'INC')
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        return f"{prefix}-{timestamp}"
