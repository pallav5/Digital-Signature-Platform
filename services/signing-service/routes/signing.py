from flask import Blueprint, request, jsonify, send_file, make_response
from flask import request as flask_request
from flask_jwt_extended import jwt_required, get_jwt_identity, decode_token
from models import db, Proposal, Signature, AuditLog
import boto3
import hashlib
import base64
import os
from datetime import datetime, timedelta, timezone
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
import io
import json
import requests


import pytz

def get_sydney_time(utc_datetime):
    """Convert UTC datetime to Sydney time with automatic DST"""
    sydney_tz = pytz.timezone('Australia/Sydney')
    if utc_datetime.tzinfo is None:
        utc_datetime = pytz.utc.localize(utc_datetime)
    return utc_datetime.astimezone(sydney_tz)

def get_user_email(user_id):
    """Fetch user email from auth service"""
    try:
        url = f'http://localhost:5001/api/auth/user/{user_id}'
        print(f"Fetching email from: {url}")
        
        auth_header = request.headers.get('Authorization', '')
        print(f"Auth header present: {bool(auth_header)}")
        
        response = requests.get(url, headers={'Authorization': auth_header}, timeout=5)
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Found email: {data.get('email')}")
            return data.get('email')
        else:
            print(f"Failed to get email: {response.status_code}")
    except Exception as e:
        print(f"Exception: {e}")
    return None


def get_user_name(user_id):
    """Fetch user name from auth service"""
    try:
        url = f'http://localhost:5001/api/auth/user/{user_id}'
        auth_header = request.headers.get('Authorization', '')
        
        response = requests.get(url, headers={'Authorization': auth_header}, timeout=2)
        if response.status_code == 200:
            return response.json().get('full_name', 'User')
    except Exception as e:
        print(f"Failed to get user name: {e}")
    return 'User'



# Notification helper
def send_notification(user_email, user_name, notification_type, extra_context=None):
    try:
        context = {'email': user_email, 'name': user_name or 'User'}
        if extra_context:
            context.update(extra_context)
        
        auth_header = request.headers.get('Authorization', '')
        
        response = requests.post('http://localhost:5006/api/notifications/send',
                     json={'type': notification_type, 'channels': ['email', 'in_app'], 'context': context},
                     headers={'Authorization': auth_header},
                     timeout=15)
        print(f"Notification sent: {response.status_code}")
    except Exception as e:
        print(f"Notification error: {e}")

import threading

def send_notification_fire_forget(user_email, user_name, notification_type,auth_header, extra_context=None):
    """Send notification without waiting for response"""
    def _send():
        try:
            context = {'email': user_email, 'name': user_name or 'User'}
            if extra_context:
                context.update(extra_context)
            
            
            requests.post('http://localhost:5006/api/notifications/send',
                         json={'type': notification_type, 'channels': ['email', 'in_app'], 'context': context},
                         headers={'Authorization': auth_header},
                         timeout=1)
            print(f"Notification queued for {user_email}")
        except Exception as e:
            print(f"Notification error (ignored): {e}")
    
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()


signing_bp = Blueprint('signing', __name__)

# Handle preflight OPTIONS requests for CORS
@signing_bp.route('/', methods=['OPTIONS'])
@signing_bp.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path=None):
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

# ── Helper Functions ──────────────────────────────────────────────

def get_kms_client():
    return boto3.client(
        'kms',
        region_name=os.getenv('AWS_REGION'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    )

def parse_user_agent(user_agent_string):
    """Extract device type, OS, and browser from User-Agent"""
    ua = user_agent_string.lower() if user_agent_string else ""
    
    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        device_type = 'Mobile'
    elif 'tablet' in ua or 'ipad' in ua:
        device_type = 'Tablet'
    else:
        device_type = 'Desktop'
    
    if 'windows' in ua:
        os_name = 'Windows'
    elif 'mac' in ua:
        os_name = 'macOS'
    elif 'linux' in ua:
        os_name = 'Linux'
    elif 'android' in ua:
        os_name = 'Android'
    elif 'iphone' in ua or 'ipad' in ua:
        os_name = 'iOS'
    else:
        os_name = 'Unknown'
    
    if 'chrome' in ua and 'edg' not in ua:
        browser = 'Chrome'
    elif 'firefox' in ua:
        browser = 'Firefox'
    elif 'safari' in ua and 'chrome' not in ua:
        browser = 'Safari'
    elif 'edg' in ua:
        browser = 'Edge'
    else:
        browser = 'Unknown'
    
    return f"{device_type} | {os_name} | {browser}"

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

def check_fraud_risk(user_id, request):
    """Check if user has high risk activity and return risk score"""
    try:
        fifteen_min_ago = datetime.utcnow() - timedelta(minutes=15)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        # Count failed logins in last 15 minutes
        failed_logins = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == 'LOGIN_FAILED',
            AuditLog.created_at >= fifteen_min_ago
        ).count()
        
        # Count failed signings in last hour
        failed_signings = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == 'SIGNING_FAILED',
            AuditLog.created_at >= one_hour_ago
        ).count()
        
        # Check unusual hour (midnight to 5am)
        current_hour = datetime.utcnow().hour
        unusual_hour = current_hour >= 0 and current_hour <= 5
        
        # Calculate risk score
        risk_score = 0.0
        if failed_logins >= 3:
            risk_score += 0.3
        if failed_logins >= 5:
            risk_score += 0.2
        if failed_signings >= 2:
            risk_score += 0.3
        if unusual_hour:
            risk_score += 0.2
        
        risk_score = min(round(risk_score, 2), 1.0)
        
        return {
            'risk_score': risk_score,
            'is_high_risk': risk_score >= 0.7,
            'failed_logins': failed_logins,
            'failed_signings': failed_signings,
            'unusual_hour': unusual_hour
        }
    except Exception as e:
        print(f"Risk check error: {e}")
        # Fail closed - block signing if we can't verify risk
        return {
            'risk_score': 1.0,
            'is_high_risk': True,
            'failed_logins': 0,
            'failed_signings': 0,
            'unusual_hour': False,
            'error': str(e)
        }

def generate_pdf(proposal, signature=None):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # ── Header bar ────────────────────────────────────────
    p.setFillColor(colors.HexColor('#1a365d'))
    p.rect(0, height - 80, width, 80, fill=True, stroke=False)
    p.setFillColor(colors.white)
    p.setFont("Helvetica-Bold", 22)
    p.drawString(40, height - 45, "Insurance Proposal")
    p.setFont("Helvetica", 11)
    p.drawString(40, height - 65, "Secure Digital Signature Platform")

    # ── Proposal details ──────────────────────────────────
    p.setFillColor(colors.HexColor('#1a365d'))
    p.setFont("Helvetica-Bold", 14)
    p.drawString(40, height - 110, "Proposal Details")
    p.setStrokeColor(colors.HexColor('#1a365d'))
    p.line(40, height - 115, width - 40, height - 115)

    details = [
        ("Proposal ID",    proposal.id),
        ("Policy Type",    proposal.policy_type),
        ("Monthly Premium", f"AUD ${proposal.premium_amount:.2f}"),
        ("Issue Date",     proposal.created_at.strftime('%d %B %Y')),
        ("Status",         proposal.status.upper()),
    ]

    p.setFont("Helvetica", 11)
    y = height - 140
    for label, value in details:
        p.setFillColor(colors.HexColor('#4a5568'))
        p.drawString(40, y, f"{label}:")
        p.setFillColor(colors.black)
        p.drawString(220, y, str(value))
        y -= 22
    # ── Features Section ─────────────────────────────────
    if proposal.features:
        p.setFillColor(colors.HexColor('#1a365d'))
        p.setFont("Helvetica-Bold", 14)
        p.drawString(40, y - 10, "Product Features")
        p.setStrokeColor(colors.HexColor('#1a365d'))
        p.line(40, y - 15, width - 40, y - 15)
        
        features = json.loads(proposal.features)
        p.setFont("Helvetica", 10)
        p.setFillColor(colors.HexColor('#2d3748'))
        fy = y - 35
        for feature in features:
            p.drawString(55, fy, f"• {feature}")
            fy -= 16
        y = fy - 10
    # ── Terms ─────────────────────────────────────────────
    p.setFillColor(colors.HexColor('#1a365d'))
    p.setFont("Helvetica-Bold", 14)
    p.drawString(40, y - 10, "Terms and Conditions")
    p.setStrokeColor(colors.HexColor('#1a365d'))
    p.line(40, y - 15, width - 40, y - 15)

    terms = [
        "1.  This insurance policy is governed by Australian law and the",
        "    Electronic Transactions Act 1999 (Cth).",
        "2.  Coverage commences upon receipt of the first premium payment.",
        "3.  Your digital signature constitutes full legal acceptance of",
        "    all terms and conditions contained in this document.",
        "4.  This document has been cryptographically signed using AWS KMS",
        "    with RSA-2048 encryption to ensure integrity and authenticity.",
        "5.  Any tampering with this document after signing will invalidate",
        "    the digital signature and void the policy.",
        "6.  All claims must be submitted within 30 days of the incident.",
        "7.  Premium payments are due on the first day of each month.",
        "8.  Policy cancellation requires 30 days written notice.",
        "9.  Personal data is handled in accordance with the Australian",
        "    Privacy Principles under the Privacy Act 1988 (Cth).",
        "10. Disputes shall be resolved under Australian Consumer Law.",
    ]

    p.setFont("Helvetica", 10)
    p.setFillColor(colors.HexColor('#2d3748'))
    ty = y - 35
    for term in terms:
        p.drawString(40, ty, term)
        ty -= 16

    # ── Signature section ─────────────────────────────────
    p.setFillColor(colors.HexColor('#1a365d'))
    p.setFont("Helvetica-Bold", 14)
    p.drawString(40, ty - 20, "Digital Signature")
    p.setStrokeColor(colors.HexColor('#1a365d'))
    p.line(40, ty - 25, width - 40, ty - 25)

    if signature:
        # Signed state - taller box for device info
        p.setFillColor(colors.HexColor('#276749'))
        p.rect(40, ty - 130, width - 80, 95, fill=True, stroke=False)
        p.setFillColor(colors.white)
        p.setFont("Helvetica-Bold", 12)
        p.drawString(55, ty - 55, "✓ DIGITALLY SIGNED — AWS KMS VERIFIED")
        
        p.setFont("Helvetica", 9)
        
        # Convert UTC to Sydney time with automatic DST
        sydney_time = get_sydney_time(signature.signed_at)
        time_str = sydney_time.strftime('%d %B %Y %H:%M:%S')
        tz_str = sydney_time.strftime('%Z')  # AEDT or AEST

        p.drawString(55, ty - 73, f"Signed at: {time_str} {tz_str}")
        
        signature_id_str = str(signature.id)
        
        p.drawString(55, ty - 88, f"Signature ID: {signature_id_str[:40]}...")
        
        # Device and IP Information Box
        p.setFillColor(colors.HexColor('#f7fafc'))
        p.rect(40, ty - 175, width - 80, 55, fill=True,  stroke=False)
        p.setFillColor(colors.HexColor('#1a365d'))
        p.setFont("Helvetica-Bold", 9)
        p.drawString(55, ty - 150, "SIGNING CERTIFICATE")
        
        p.setFont("Helvetica", 8)
        p.setFillColor(colors.HexColor('#4a5568'))
        
        device_line = f"Device: {signature.device_info if signature.device_info else 'Unknown'}"
        p.drawString(55, ty - 164, device_line)
        
        ip_line = f"IP Address: {signature.ip_address if signature.ip_address else 'Unknown'}"
        p.drawString(55, ty - 175, ip_line)
        
        # Cryptographic Signature Hash
        p.setFillColor(colors.HexColor('#f7fafc'))
        p.rect(40, ty - 230, width - 80, 45, fill=True, stroke=False)
        p.setFillColor(colors.HexColor('#4a5568'))
        p.setFont("Helvetica", 8)
        p.drawString(55, ty - 200, "Cryptographic Signature (SHA-256 / RSA):")
        hash_display = signature.signature_hash[:80] + "..." \
            if len(signature.signature_hash) > 80 \
            else signature.signature_hash
        p.drawString(55, ty - 213, hash_display)
        p.drawString(55, ty - 226, f"KMS Key: {signature.kms_key_id[-40:] if signature.kms_key_id else 'N/A'}")

    else:
        # Unsigned state
        p.setFillColor(colors.HexColor('#fff9c4'))
        p.rect(40, ty - 90, width - 80, 55, fill=True, stroke=False)
        p.setFillColor(colors.HexColor('#744210'))
        p.setFont("Helvetica-Bold", 12)
        p.drawString(55, ty - 50, "AWAITING DIGITAL SIGNATURE")
        p.setFont("Helvetica", 10)
        p.drawString(55, ty - 68, "Please review this document and click 'I Accept & Sign' to sign.")

    # ── Footer ────────────────────────────────────────────
    p.setFillColor(colors.HexColor('#e2e8f0'))
    p.rect(10, 0, width, 35, fill=True, stroke=False)
    p.setFillColor(colors.HexColor('#4a5568'))
    p.setFont("Helvetica", 8)
    p.drawString(40, 14, "This document was generated by the Secure Digital Signature Platform. "
                 "Compliant with Electronic Transactions Act 1999 (Cth).")
    p.drawRightString(width - 40, 14, f"Generated: {datetime.utcnow().strftime('%d %B %Y')}")

    p.save()
    buffer.seek(0)
    return buffer.getvalue()

# ── Routes ───────────────────────────────────────────────────────

@signing_bp.route('/proposal', methods=['POST'])
@jwt_required()
def create_proposal():
    user_id = get_jwt_identity()
    data = request.get_json()

    required = ['policy_type', 'premium_amount']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    proposal = Proposal(
        user_id=user_id,
        policy_type=data['policy_type'],
        premium_amount=float(data['premium_amount']),
        status='draft',
        features=json.dumps(data.get('features', [])),
        product_description=data.get('description', '')
    )
    db.session.add(proposal)
    db.session.commit()

    pdf_bytes = generate_pdf(proposal)
    pdf_dir = 'storage/proposals'
    os.makedirs(pdf_dir, exist_ok=True)
    pdf_path = f"{pdf_dir}/{proposal.id}.pdf"
    with open(pdf_path, 'wb') as f:
        f.write(pdf_bytes)

    proposal.pdf_path = pdf_path
    db.session.commit()

    log_action(user_id, 'PROPOSAL_CREATED', request)

     # Send notification with user email
    try:
        user_email = get_user_email(user_id)
        user_name = data.get('full_name', 'User')
        
        if user_email:
            send_notification(user_email, user_name, 'PROPOSAL_CREATED',
                             {'proposal_id': str(proposal.id),
                              'policy_type': proposal.policy_type,
                              'premium': proposal.premium_amount, 
                              'sign_url': 'http://localhost:3000/dashboard'})
        else:
            print(f"No email found for user {user_id}")
    except Exception as e:
        print(f"Notification error: {e}")
    
    return jsonify({
        'message': 'Proposal created successfully',
        'proposal_id': proposal.id,
        'policy_type': proposal.policy_type,
        'premium_amount': proposal.premium_amount,
        'status': proposal.status
    }), 201


@signing_bp.route('/sign/<proposal_id>', methods=['POST'])
@jwt_required()
def sign_proposal(proposal_id):
    user_id = get_jwt_identity()
    
    # Check fraud risk
    risk_data = check_fraud_risk(user_id, request)
    
    if risk_data['is_high_risk']:
        log_action(user_id, 'SIGNING_BLOCKED_HIGH_RISK', request, risk_data['risk_score'])
        return jsonify({
            'error': 'Signing blocked due to high risk activity',
            'risk_score': risk_data['risk_score'],
            'reason': {
                'failed_logins_last_15min': risk_data['failed_logins'],
                'failed_signings_last_hour': risk_data['failed_signings'],
                'unusual_hour': risk_data['unusual_hour']
            },
            'contact_support': True
        }), 403
    
    # Capture device information
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    device_info = parse_user_agent(user_agent)

    proposal = Proposal.query.get(proposal_id)
    if not proposal:
        return jsonify({'error': 'Proposal not found'}), 404

    if proposal.status == 'signed':
        return jsonify({'error': 'Proposal already signed'}), 400

    # Generate PDF without signature first (for hashing)
    pdf_bytes = generate_pdf(proposal, None)
    pdf_dir = 'storage/proposals'
    os.makedirs(pdf_dir, exist_ok=True)
    pdf_path = f"{pdf_dir}/{proposal.id}.pdf"
    
    # Create document hash from the unsigned PDF
    document_hash = hashlib.sha256(pdf_bytes).digest()

    # Sign with AWS KMS
    try:
        kms = get_kms_client()
        response = kms.sign(
            KeyId=os.getenv('AWS_KMS_KEY_ID'),
            Message=document_hash,
            MessageType='DIGEST',
            SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
        )
        signature_bytes = response['Signature']
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

    except Exception as e:
        log_action(user_id, 'SIGNING_FAILED', request, risk_score=0.5)
        return jsonify({'error': f'KMS signing failed: {str(e)}'}), 500

        # Create signature record
    signed_at = datetime.utcnow()
    signature = Signature(
        proposal_id=proposal.id,
        user_id=user_id,
        signature_hash=signature_b64,
        document_hash=document_hash.hex(),
        kms_key_id=os.getenv('AWS_KMS_KEY_ID'),
        signed_at=signed_at,
        is_valid=True,
        ip_address=ip_address,
        device_info=device_info,
        user_agent=user_agent
    )
    db.session.add(signature)

    # Generate FINAL PDF with signature and store final hash
    final_pdf_bytes = generate_pdf(proposal, signature)
    with open(pdf_path, 'wb') as f:
        f.write(final_pdf_bytes)
    
    # Store final PDF hash for tamper detection
    final_pdf_hash = hashlib.sha256(final_pdf_bytes).hexdigest()
    signature.final_pdf_hash = final_pdf_hash
    
    proposal.pdf_path = pdf_path
    proposal.status = 'signed'
    db.session.commit()  # Only ONE commit

    log_action(user_id, 'PROPOSAL_SIGNED', request)

    # Send notification
    try:
        user_email = get_user_email(user_id)
        user_name = get_user_name(user_id)
        auth_header = request.headers.get('Authorization', '')
        
        if user_email:
            send_notification_fire_forget(user_email, user_name, 'DOCUMENT_SIGNED', auth_header,
                                         {'proposal_id': str(proposal.id),
                                          'signed_at': signed_at.isoformat(),
                                          'signature_id': str(signature.id),
                                          'download_url': 'http://localhost:3000/dashboard'})
    except Exception as e:
        print(f"Notification error (ignored): {e}")

    return jsonify({
        'message': 'Proposal signed successfully',
        'proposal_id': proposal.id,
        'signature_id': signature.id,
        'signed_at': signature.signed_at.isoformat(),
        'kms_key_used': os.getenv('AWS_KMS_KEY_ID'),
        'ip_address': ip_address,
        'device': device_info
    }), 200


@signing_bp.route('/verify/<proposal_id>', methods=['GET'])
@jwt_required()
def verify_signature(proposal_id):
    user_id = get_jwt_identity()

    proposal = Proposal.query.get(proposal_id)
    if not proposal:
        return jsonify({'error': 'Proposal not found'}), 404

    signature = Signature.query.filter_by(proposal_id=proposal_id).first()

    if not signature:
        return jsonify({'error': 'No signature found'}), 404

    if not signature.document_hash:
        return jsonify({
            'error': 'This proposal was signed before verification update. Please create a new proposal.',
            'is_valid': False,
            'needs_resign': True
        }), 200

    # ==============================================
    # STEP 1: Verify stored hash with AWS KMS
    # ==============================================
    try:
        stored_hash = bytes.fromhex(signature.document_hash)
        signature_bytes = base64.b64decode(signature.signature_hash)

        kms = get_kms_client()
        response = kms.verify(
            KeyId=os.getenv('AWS_KMS_KEY_ID'),
            Message=stored_hash,
            MessageType='DIGEST',
            Signature=signature_bytes,
            SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
        )
        is_signature_valid = response['SignatureValid']
        print(f"Signature valid: {is_signature_valid}")

    except Exception as e:
        print(f"Verification error: {e}")
        return jsonify({'error': f'Verification failed: {str(e)}'}), 500

    # ==============================================
    # STEP 2: Check if final PDF has been tampered
    # ==============================================
    is_tampered = False
    if signature.final_pdf_hash and proposal.pdf_path and os.path.exists(proposal.pdf_path):
        with open(proposal.pdf_path, 'rb') as f:
            current_pdf_bytes = f.read()
        current_hash = hashlib.sha256(current_pdf_bytes).hexdigest()
        
        print(f"Stored final PDF hash: {signature.final_pdf_hash[:32]}...")
        print(f"Current PDF hash: {current_hash[:32]}...")
        
        if current_hash != signature.final_pdf_hash:
            is_tampered = True
            print("⚠️ FINAL PDF TAMPERED! File has been modified after signing")

    # ==============================================
    # STEP 3: Final result
    # ==============================================
    is_valid = is_signature_valid and not is_tampered

    log_action(user_id, 'SIGNATURE_VERIFIED', request)

    return jsonify({
        'proposal_id': proposal_id,
        'is_valid': is_valid,
        'is_signature_valid': is_signature_valid,
        'is_tampered': is_tampered,
        'signed_at': signature.signed_at.isoformat(),
        'kms_key_id': signature.kms_key_id,
        'device_info': signature.device_info,
        'ip_address': signature.ip_address,
        'message': 'Document is authentic' if is_valid else ('Document has been tampered' if is_tampered else 'Signature is invalid')
    }), 200

@signing_bp.route('/proposals', methods=['GET'])
@jwt_required()
def get_proposals():
    user_id = get_jwt_identity()
    proposals = Proposal.query.filter_by(user_id=user_id).all()

    return jsonify([{
        'id': p.id,
        'policy_type': p.policy_type,
        'premium_amount': p.premium_amount,
        'status': p.status,
        'created_at': p.created_at.isoformat()
    } for p in proposals]), 200
@signing_bp.route('/proposal/<proposal_id>/view', methods=['GET'])
def view_pdf(proposal_id):
    # Get token from query parameter
    token = flask_request.args.get('token')
    if not token:
        return jsonify({'error': 'Token required'}), 401

    try:
        decoded = decode_token(token)
        user_id = decoded.get('sub')
    except Exception as e:
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401

    proposal = Proposal.query.get(proposal_id)
    if not proposal:
        return jsonify({'error': 'Proposal not found'}), 404

    # READ EXISTING PDF - DO NOT REGENERATE
    if not proposal.pdf_path or not os.path.exists(proposal.pdf_path):
        return jsonify({'error': 'PDF file not found'}), 404
    
    with open(proposal.pdf_path, 'rb') as f:
        pdf_bytes = f.read()

    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline'
    return response


@signing_bp.route('/proposal/<proposal_id>/pdf', methods=['GET'])
@jwt_required()
def download_pdf(proposal_id):
    user_id = get_jwt_identity()

    proposal = Proposal.query.get(proposal_id)
    if not proposal:
        return jsonify({'error': 'Proposal not found'}), 404

    # COMMENT OUT THIS CHECK FOR NOW
    # if proposal.user_id != user_id:
    #     return jsonify({'error': 'Unauthorized'}), 403

    if proposal.status != 'signed':
        return jsonify({'error': 'Proposal must be signed before downloading'}), 400

    signature = Signature.query.filter_by(proposal_id=proposal_id).first()
    pdf_bytes = generate_pdf(proposal, signature)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"signed_proposal_{proposal_id[:8]}.pdf"
    )

@signing_bp.route('/proposal/<proposal_id>', methods=['DELETE'])
@jwt_required()
def delete_proposal(proposal_id):
    user_id = get_jwt_identity()
    
    proposal = Proposal.query.get(proposal_id)
    if not proposal:
        return jsonify({'error': 'Proposal not found'}), 404
    
    # Convert UUID to string for comparison
    if str(proposal.user_id) != str(user_id):
        return jsonify({'error': f'Unauthorized. Proposal belongs to {proposal.user_id}, you are {user_id}'}), 403
    
    if proposal.status == 'signed':
        return jsonify({'error': 'Cannot delete signed proposals'}), 400
    
    if proposal.pdf_path and os.path.exists(proposal.pdf_path):
        try:
            os.remove(proposal.pdf_path)
        except Exception as e:
            print(f"Error deleting PDF: {e}")
    
    db.session.delete(proposal)
    db.session.commit()
    
    log_action(user_id, 'PROPOSAL_DELETED', request)
    
    return jsonify({'message': 'Proposal deleted successfully'}), 200