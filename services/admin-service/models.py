from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

# Admin User Model (only for admin service)
class AdminUser(db.Model):
    __tablename__ = 'admin_users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='admin')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)


# These models already exist in your database
# We're just declaring them here so SQLAlchemy knows about them
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True)
    email = db.Column(db.String(255))
    password_hash = db.Column(db.String(255))
    full_name = db.Column(db.String(255))
    mfa_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36))
    action = db.Column(db.String(255))
    ip_address = db.Column(db.String(50))
    device_info = db.Column(db.Text)
    risk_score = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Proposal(db.Model):
    __tablename__ = 'proposals'
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36))
    policy_type = db.Column(db.String(100))
    premium_amount = db.Column(db.Float)
    pdf_path = db.Column(db.String(500))
    status = db.Column(db.String(50), default='draft')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Signature(db.Model):
    __tablename__ = 'signatures'
    id = db.Column(db.String(36), primary_key=True)
    proposal_id = db.Column(db.String(36))
    user_id = db.Column(db.String(36))
    signature_hash = db.Column(db.String(500))
    kms_key_id = db.Column(db.String(255))
    signed_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_valid = db.Column(db.Boolean, default=True)
    document_hash = db.Column(db.String(500))
    ip_address = db.Column(db.String(50))
    device_info = db.Column(db.Text)
    user_agent = db.Column(db.Text)
    final_pdf_hash = db.Column(db.String(500))


class FraudEvent(db.Model):
    __tablename__ = 'fraud_events'
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36))
    event_type = db.Column(db.String(100))
    risk_score = db.Column(db.Float, default=0.0)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)