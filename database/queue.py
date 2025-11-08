from .base_model import BaseModel


class QueueModel(BaseModel):
    table = 'queue'
    fields = ['id', 'data', 'status', 'created_at','processed_at','consumer_id']

    def find_by_consumer_id(self, consumer_id):
        cur = self.conn.execute('SELECT * FROM companies WHERE consumer_id = ?', (consumer_id))
        r = cur.fetchone()
        return dict(r) if r else None

