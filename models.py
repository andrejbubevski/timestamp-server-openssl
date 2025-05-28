from datetime import datetime
from app import db

class Timestamp(db.Model):
    __tablename__ = 'timestamps'
    id = db.Column(db.Integer, primary_key=True)
    data_hash = db.Column(db.LargeBinary, nullable=False)
    timestamp_token = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Timestamp {self.id} {self.created_at}>'