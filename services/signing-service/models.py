from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import uuid
import pytz

db = SQLAlchemy()

class Proposal(db.Model):
    __tablename__ = 'proposals'

    id = db.Column(db.String(36), primary_key=True, 
                   default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), nullable=False)
    policy_type = db.Column(db.String(100), nullable=False)
    premium_amount = db.Column(db.Float, nullable=True)
    pdf_path = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(50), default='draft')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

     # ADD THESE TWO LINES:
    features = db.Column(db.Text, nullable=True)
    product_description = db.Column(db.Text, nullable=True)

class Signature(db.Model):
    __tablename__ = 'signatures'

    id = db.Column(db.String(36), primary_key=True, 
                   default=lambda: str(uuid.uuid4()))
    proposal_id = db.Column(db.String(36), 
                            db.ForeignKey('proposals.id'), nullable=False)
    user_id = db.Column(db.String(36), nullable=False)
    signature_hash = db.Column(db.String(500), nullable=True)
    kms_key_id = db.Column(db.String(255), nullable=True)
    signed_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Australia/Sydney')))
    is_valid = db.Column(db.Boolean, default=True)

    document_hash = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    device_info = db.Column(db.Text, nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.String(36), primary_key=True, 
                   default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    device_info = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)