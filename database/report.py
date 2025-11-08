from .base_model import BaseModel


class ReportModel(BaseModel):
    table = 'report'
    fields = ['id', 'root_cause', 'environment', 'severity','summary','recommendation','consumer_id','created_at']

    def find_by_environment(self, environment):
        cur = self.conn.execute('SELECT * FROM companies WHERE environment = ?', (environment))
        r = cur.fetchone()
        return dict(r) if r else None
