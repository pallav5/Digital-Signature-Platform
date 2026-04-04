from flask import Blueprint, request, jsonify
from models import db, User, AuditLog
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import bcrypt
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

def log_action(user_id, action, request, risk_score=0.0):
    log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=request.remote_addr,
        device_info=request.headers.get('User-Agent'),
        risk_score=risk_score
    )
    db.session.add(log)
    db.session.commit()

# ── Register ──────────────────────────────────────────────
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    required = ['email', 'password', 'full_name']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409

    password_hash = bcrypt.hashpw(
        data['password'].encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    user = User(
        email=data['email'],
        password_hash=password_hash,
        full_name=data['full_name']
    )
    db.session.add(user)
    db.session.commit()

    log_action(user.id, 'USER_REGISTERED', request)

    return jsonify({
        'message': 'User registered successfully',
        'user_id': user.id
    }), 201

# ── Login ─────────────────────────────────────────────────
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400

    user = User.query.filter_by(email=data['email']).first()

    # Check credentials
    credentials_valid = user and bcrypt.checkpw(
        data['password'].encode('utf-8'),
        user.password_hash.encode('utf-8')
    )

    if not credentials_valid:
    # Send failed login attempt to fraud service
    
        try:
            import requests
            fraud_data = {
                'event_type': 'LOGIN_FAILED',
                'failed_attempts': 1,
                'email': data.get('email'),
                'user_id': str(user.id) if user else None  # ADD THIS LINE
            }
            # Get token from request header if present
            auth_header = request.headers.get('Authorization')
            headers = {'Authorization': auth_header} if auth_header else {}
            requests.post('http://localhost:5005/api/fraud/analyse', 
                        json=fraud_data,
                        headers=headers,
                        timeout=1)
        except Exception as e:
            print(f"Fraud service error: {e}")
        
        log_action(user.id if user else None, 'LOGIN_FAILED', request, risk_score=0.8)
        return jsonify({'error': 'Invalid credentials'}), 401

    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 403

    # If MFA is enabled, require TOTP before issuing token
    if user.mfa_enabled:
        totp_code = data.get('totp_code')
        if not totp_code:
            return jsonify({
                'mfa_required': True,
                'message': 'Please provide your MFA code'
            }), 200

        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(totp_code, valid_window=1):
            # Send MFA failure to fraud service
            try:
                import requests
                fraud_data = {
                    'event_type': 'MFA_FAILED',
                    'failed_attempts': 1
                }
                auth_header = request.headers.get('Authorization')
                headers = {'Authorization': auth_header} if auth_header else {}
                requests.post('http://localhost:5005/api/fraud/analyse', 
                             json=fraud_data,
                             headers=headers,
                             timeout=1)
            except Exception as e:
                print(f"Fraud service error: {e}")
            
            log_action(user.id, 'MFA_FAILED', request, risk_score=0.9)
            return jsonify({'error': 'Invalid MFA code'}), 401

    # Send successful login to fraud service
    try:
        import requests
        fraud_data = {
            'event_type': 'LOGIN_SUCCESS',
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
        auth_header = request.headers.get('Authorization')
        headers = {'Authorization': auth_header} if auth_header else {}
        requests.post('http://localhost:5005/api/fraud/analyse', 
                     json=fraud_data,
                     headers=headers,
                     timeout=1)
    except Exception as e:
        print(f"Fraud service error: {e}")

    token = create_access_token(
        identity=user.id,
        expires_delta=timedelta(hours=8)
    )

    log_action(user.id, 'LOGIN_SUCCESS', request)

    return jsonify({
        'access_token': token,
        'user': {
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'mfa_enabled': user.mfa_enabled
        }
    }), 200

# ── Setup MFA ─────────────────────────────────────────────
@auth_bp.route('/mfa/setup', methods=['POST'])
@jwt_required()
def setup_mfa():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Generate a new TOTP secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='InsurancePlatform'
    )

    # Generate QR code
    qr = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    # Save secret temporarily (not enabled until verified)
    user.mfa_secret = secret
    db.session.commit()

    log_action(user.id, 'MFA_SETUP_INITIATED', request)

    return jsonify({
        'secret': secret,
        'qr_code': f'data:image/png;base64,{qr_base64}',
        'message': 'Scan QR code with Google Authenticator then verify'
    }), 200

# ── Verify and Enable MFA ─────────────────────────────────
@auth_bp.route('/mfa/verify', methods=['POST'])
@jwt_required()
def verify_mfa():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()

    if not user or not user.mfa_secret:
        return jsonify({'error': 'MFA setup not initiated'}), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(data.get('totp_code', '')):
        return jsonify({'error': 'Invalid code — try again'}), 401

    user.mfa_enabled = True
    db.session.commit()

    log_action(user.id, 'MFA_ENABLED', request)

    return jsonify({'message': 'MFA enabled successfully'}), 200

# ── Get current user ──────────────────────────────────────
@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_me():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'id': user.id,
        'email': user.email,
        'full_name': user.full_name,
        'mfa_enabled': user.mfa_enabled,
        'created_at': user.created_at.isoformat()
    }), 200