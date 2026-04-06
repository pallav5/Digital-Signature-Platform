from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, FraudEvent, AuditLog
from datetime import datetime
import json
from sqlalchemy import text   # ADD THIS LINE


fraud_bp = Blueprint('fraud', __name__)

# Helper to get allowed origin
def get_allowed_origin():
    origin = request.headers.get('Origin', '')
    allowed_origins = ['http://localhost:3000', 'http://192.168.1.106:3000']
    if origin in allowed_origins:
        return origin
    return 'http://localhost:3000'  # default

# Handle preflight OPTIONS requests
@fraud_bp.route('/', methods=['OPTIONS'])
@fraud_bp.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path=None):
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

@fraud_bp.route('/analyse', methods=['POST', 'OPTIONS'])
@jwt_required(optional=True)
def analyse():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
        return response
    
    try:
        data = request.get_json()
        print(f"Fraud analyse received: {data}")
        
        # Get user_id from JWT token
        user_id = get_jwt_identity()
        if not user_id:
            user_id = data.get('user_id')
        
        if not user_id:
            response = jsonify({'error': 'User ID required'})
            response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
            return response, 400
        
        event_type = data.get('event_type', 'UNKNOWN')
        
        # Get user's recent activity from database
        from datetime import datetime, timedelta
        fifteen_min_ago = datetime.utcnow() - timedelta(minutes=15)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        # Count failed logins from AuditLog (not FraudEvent)
        from models import AuditLog
        failed_logins = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == 'LOGIN_FAILED',
            AuditLog.created_at >= fifteen_min_ago
        ).count()
        print(f"Failed logins for user {user_id} in last 15 min: {failed_logins}")
        
        # Count MFA failures from AuditLog
        mfa_failures = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == 'MFA_FAILED',
            AuditLog.created_at >= fifteen_min_ago
        ).count()
        print(f"MFA failures: {mfa_failures}")
        
        # Count failed signings in last hour
        # Count failed signings from AuditLog
        failed_signings = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == 'SIGNING_FAILED',
            AuditLog.created_at >= one_hour_ago
        ).count()
        print(f"Failed signings: {failed_signings}")
       
        # Count successful signings from AuditLog
        successful_signings = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == 'PROPOSAL_SIGNED',
            AuditLog.created_at >= one_hour_ago
        ).count()
        print(f"Successful signings: {successful_signings}")
        
        # Check unusual hour
        current_hour = datetime.utcnow().hour
        unusual_hour = current_hour >= 0 and current_hour <= 5
        
            # Count proposals created in last hour using raw SQL
        try:
            print(f"DEBUG: Counting proposals for user_id: {user_id}")
            
            result = db.session.execute(
                text("SELECT COUNT(*) FROM proposals WHERE user_id = :user_id AND created_at >= NOW() - INTERVAL '1 hour'"),
                {'user_id': str(user_id)}
            )
            recent_proposals = result.scalar()
            print(f"Recent proposals (last hour): {recent_proposals}")
        except Exception as e:
            print(f"Error counting proposals: {e}")
            recent_proposals = 0
        
        # Calculate risk score
        risk_score = 0.0
        
        if failed_logins >= 3:
            risk_score += 0.3
        if failed_logins >= 5:
            risk_score += 0.2
        if mfa_failures >= 2:
            risk_score += 0.4
        if failed_signings >= 2:
            risk_score += 0.3
        if unusual_hour:
            risk_score += 0.2
        if successful_signings >= 5:
            risk_score += 0.2


        #  Rapid proposal creation check
        if recent_proposals >= 5:
            risk_score += 0.3  # +0.3 for 5+ proposals in an hour
        if recent_proposals >= 10:
            risk_score += 0.2  # +0.5 total for 10+ proposals    
        
        risk_score = min(round(risk_score, 2), 1.0)
        
        # Determine risk level
        if risk_score >= 0.7:
            risk_level = 'HIGH'
            alert = True
            message = '🚫 HIGH RISK - Signing blocked. Contact support.'
        elif risk_score >= 0.4:
            risk_level = 'MEDIUM'
            alert = True
            message = '⚠️ SUSPICIOUS ACTIVITY - Please verify your identity to continue.'
        else:
            risk_level = 'LOW'
            alert = False
            message = '✓ Normal activity'
        
        # Create fraud event
        event = FraudEvent(
            user_id=str(user_id),
            event_type=event_type,
            risk_score=risk_score,
            details=json.dumps({
                'failed_logins': failed_logins,
                'mfa_failures': mfa_failures,
                'failed_signings': failed_signings,
                'successful_signings': successful_signings,
                'unusual_hour': unusual_hour,
                'risk_level': risk_level
            })
        )
        db.session.add(event)
        db.session.commit()
        
        response = jsonify({
            'user_id': str(user_id),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'alert': alert,
            'can_sign': risk_score < 0.7,
            'message': message,
            'details': {
                'failed_logins': failed_logins,
                'mfa_failures': mfa_failures,
                'unusual_hour': unusual_hour
            }
        })
        response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
        
    except Exception as e:
        print(f"Error in analyse: {e}")
        response = jsonify({'error': str(e), 'can_sign': True})
        response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
        return response, 500

@fraud_bp.route('/history', methods=['GET', 'OPTIONS'])
@jwt_required(optional=True)
def history():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,OPTIONS")
        return response
    
    try:
        user_id = get_jwt_identity()
        
        if not user_id:
            response = jsonify([])
            response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
            return response
        
        # Get fraud events for this user
        events = FraudEvent.query.filter_by(
            user_id=str(user_id)
        ).order_by(FraudEvent.created_at.desc()).limit(50).all()
        
        result = []
        for e in events:
            result.append({
                'id': str(e.id),
                'event_type': e.event_type,
                'risk_score': e.risk_score,
                'created_at': e.created_at.isoformat()
            })
        
        response = jsonify(result)
        response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
        
    except Exception as e:
        print(f"Error in history: {e}")
        response = jsonify([])
        response.headers.add("Access-Control-Allow-Origin", get_allowed_origin())
        return response