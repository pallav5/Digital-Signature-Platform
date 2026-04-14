from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from flask_cors import CORS
from models import db, AdminUser, AuditLog, User, Proposal, Signature, FraudEvent
from dotenv import load_dotenv
import os
from datetime import timedelta
import bcrypt

load_dotenv()

app = Flask(__name__)

CORS(app, origins=["http://localhost:3000", "http://192.168.1.106:3000"])

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

db.init_app(app)
jwt = JWTManager(app)

# Admin login endpoint
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    admin = AdminUser.query.filter_by(email=email).first()
    
    if not admin or not bcrypt.checkpw(password.encode('utf-8'), admin.password_hash.encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not admin.is_active:
        return jsonify({'error': 'Account disabled'}), 403
    
    access_token = create_access_token(identity=str(admin.id), additional_claims={'role': 'admin'})
    
    return jsonify({
        'access_token': access_token,
        'admin': {
            'id': admin.id,
            'email': admin.email,
            'full_name': admin.full_name,
            'role': admin.role
        }
    }), 200

# Dashboard stats
@app.route('/api/admin/stats', methods=['GET'])
@jwt_required()
def get_stats():
    current_user_id = get_jwt_identity()
    admin = AdminUser.query.get(current_user_id)
    
    if not admin or admin.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    total_users = User.query.count()
    total_proposals = Proposal.query.count()
    total_signatures = Signature.query.count()
    signed_proposals = Proposal.query.filter_by(status='signed').count()
    high_risk_events = FraudEvent.query.filter(FraudEvent.risk_score >= 0.7).count()
    
    # Recent activity
    recent_audits = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()
    
    return jsonify({
        'stats': {
            'total_users': total_users,
            'total_proposals': total_proposals,
            'total_signatures': total_signatures,
            'signed_proposals': signed_proposals,
            'pending_proposals': total_proposals - signed_proposals,
            'high_risk_events': high_risk_events
        },
        'recent_activity': [{
            'id': a.id,
            'user_id': a.user_id,
            'action': a.action,
            'ip_address': a.ip_address,
            'device_info': a.device_info,
            'risk_score': a.risk_score,
            'created_at': a.created_at.isoformat()
        } for a in recent_audits]
    }), 200

# Get all users
@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user_id = get_jwt_identity()
    admin = AdminUser.query.get(current_user_id)
    
    if not admin or admin.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = User.query.order_by(User.created_at.desc()).all()
    
    return jsonify([{
        'id': u.id,
        'email': u.email,
        'full_name': u.full_name,
        'mfa_enabled': u.mfa_enabled,
        'is_active': u.is_active,
        'created_at': u.created_at.isoformat()
    } for u in users]), 200

# Get single user details
@app.route('/api/admin/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    current_user_id = get_jwt_identity()
    admin = AdminUser.query.get(current_user_id)
    
    if not admin or admin.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    proposals = Proposal.query.filter_by(user_id=user_id).all()
    signatures = Signature.query.filter_by(user_id=user_id).all()
    fraud_events = FraudEvent.query.filter_by(user_id=user_id).order_by(FraudEvent.created_at.desc()).limit(20).all()
    
    return jsonify({
        'user': {
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'mfa_enabled': user.mfa_enabled,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat()
        },
        'proposals': [{
            'id': p.id,
            'policy_type': p.policy_type,
            'premium_amount': p.premium_amount,
            'status': p.status,
            'created_at': p.created_at.isoformat()
        } for p in proposals],
        'signatures': [{
            'id': s.id,
            'proposal_id': s.proposal_id,
            'signed_at': s.signed_at.isoformat(),
            'ip_address': s.ip_address,
            'device_info': s.device_info
        } for s in signatures],
        'fraud_events': [{
            'id': f.id,
            'event_type': f.event_type,
            'risk_score': f.risk_score,
            'created_at': f.created_at.isoformat()
        } for f in fraud_events]
    }), 200

# Update user status (activate/disable)
@app.route('/api/admin/users/<user_id>/status', methods=['PUT'])
@jwt_required()
def update_user_status(user_id):
    current_user_id = get_jwt_identity()
    admin = AdminUser.query.get(current_user_id)
    
    if not admin or admin.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    is_active = data.get('is_active')
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.is_active = is_active
    db.session.commit()
    
    return jsonify({'message': f'User {"activated" if is_active else "disabled"} successfully'}), 200

# Get all proposals
@app.route('/api/admin/proposals', methods=['GET'])
@jwt_required()
def get_all_proposals():
    current_user_id = get_jwt_identity()
    admin = AdminUser.query.get(current_user_id)
    
    if not admin or admin.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    proposals = Proposal.query.order_by(Proposal.created_at.desc()).all()
    
    return jsonify([{
        'id': p.id,
        'user_id': p.user_id,
        'policy_type': p.policy_type,
        'premium_amount': p.premium_amount,
        'status': p.status,
        'created_at': p.created_at.isoformat()
    } for p in proposals]), 200

# Get all signatures
@app.route('/api/admin/signatures', methods=['GET'])
@jwt_required()
def get_all_signatures():
    current_user_id = get_jwt_identity()
    admin = AdminUser.query.get(current_user_id)
    
    if not admin or admin.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    signatures = Signature.query.order_by(Signature.signed_at.desc()).all()
    
    return jsonify([{
        'id': s.id,
        'proposal_id': s.proposal_id,
        'user_id': s.user_id,
        'signed_at': s.signed_at.isoformat(),
        'ip_address': s.ip_address,
        'device_info': s.device_info,
        'is_valid': s.is_valid
    } for s in signatures]), 200

# Get fraud events
@app.route('/api/admin/fraud-events', methods=['GET'])
@jwt_required()
def get_fraud_events():
    current_user_id = get_jwt_identity()
    admin = AdminUser.query.get(current_user_id)
    
    if not admin or admin.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    fraud_events = FraudEvent.query.order_by(FraudEvent.risk_score.desc(), FraudEvent.created_at.desc()).all()
    
    return jsonify([{
        'id': f.id,
        'user_id': f.user_id,
        'event_type': f.event_type,
        'risk_score': f.risk_score,
        'details': f.details,
        'created_at': f.created_at.isoformat()
    } for f in fraud_events]), 200

# Get audit logs
@app.route('/api/admin/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    current_user_id = get_jwt_identity()
    admin = AdminUser.query.get(current_user_id)
    
    if not admin or admin.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    limit = request.args.get('limit', 100, type=int)
    audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    
    return jsonify([{
        'id': a.id,
        'user_id': a.user_id,
        'action': a.action,
        'ip_address': a.ip_address,
        'device_info': a.device_info,
        'risk_score': a.risk_score,
        'created_at': a.created_at.isoformat()
    } for a in audit_logs]), 200

# Create default admin user (run once)
@app.route('/api/admin/setup', methods=['POST'])
def setup_admin():
    # Check if admin already exists
    if AdminUser.query.first():
        return jsonify({'message': 'Admin already exists'}), 400
    
    data = request.get_json()
    password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    admin = AdminUser(
        email=data['email'],
        password_hash=password_hash,
        full_name=data['full_name'],
        role='admin',
        is_active=True
    )
    db.session.add(admin)
    db.session.commit()
    
    return jsonify({'message': 'Admin user created successfully'}), 201

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5008, debug=True)