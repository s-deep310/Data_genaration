from typing import List, Dict, Any
from .base_model import BaseModel

class ClassifierOutputsModel(BaseModel):
    table = 'classifier_outputs'
    fields = [
        'id', 'payload_id', 'environment', 'severity_id', 'bert_score', 'rule_score', 
        'combined_score', 'matched_pattern', 'is_incident', 'source_type', 'payload', 
        'processed_at', 'corrective_action','approver_id','approver_suggestion','approved_at'
    ]

    def find_unprocessed(self) -> List[Dict[str, Any]]:
        """
        Fetch all rows where processed_at IS NULL.
        """
        cur = self.conn.execute(f"SELECT * FROM {self.table} WHERE processed_at IS NULL")
        return [dict(row) for row in cur.fetchall()]

    def update_by_payload_id(self, payload_id: str, update_fields: Dict[str, Any]) -> None:
        """
        Update columns for a record identified by payload_id.
        """
        assignments = ', '.join([f"{k} = ?" for k in update_fields.keys()])
        values = tuple(update_fields.values()) + (payload_id)
        sql = f"UPDATE {self.table} SET {assignments} WHERE payload_id = ?"
        self.conn.execute(sql, values)
        self.conn.commit()
