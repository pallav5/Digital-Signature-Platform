from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import smtplib
import os
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import threading


notification_bp = Blueprint('notification', __name__)

# In-memory storage for notifications (replace with database in production)
notifications_db = []
user_notifications = {}

# Email templates
EMAIL_TEMPLATES = {
    'PROPOSAL_CREATED': {
        'subject': '📄 Your Insurance Proposal is Ready',
        'body': """Dear {name},

Your insurance proposal has been created successfully.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 PROPOSAL DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Proposal ID: {proposal_id}
Policy Type: {policy_type}
Premium: AUD ${premium}/month
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Click here to review and sign: {sign_url}

Regards,
Insurance Platform Team
🔒 This is an automated message. Please do not reply."""
    },
    'DOCUMENT_SIGNED': {
        'subject': '✅ Document Signed Successfully',
        'body': """Dear {name},

Your insurance document has been digitally signed successfully.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 SIGNATURE DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Proposal ID: {proposal_id}
Signed at: {signed_at}
Signature ID: {signature_id}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Download your signed document: {download_url}

Regards,
Insurance Platform Team
🔒 This is an automated message. Please do not reply."""
    },
    'SECURITY_ALERT': {
        'subject': '⚠️ Security Alert - Immediate Action Required',
        'body': """Dear {name},

Suspicious activity has been detected on your account.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ ALERT DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: {risk_score}
Activity: {activity_type}
Time: {timestamp}
IP Address: {ip_address}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If this was not you, please contact support immediately.

Regards,
Insurance Platform Team
🔒 This is an automated message. Please do not reply."""
    },
    'MFA_ENABLED': {
        'subject': '🔐 MFA Enabled on Your Account',
        'body': """Dear {name},

Multi-factor authentication has been enabled on your account.

If you did not perform this action, please contact support immediately.

Regards,
Insurance Platform Team"""
    },
    'POLICY_ACTIVATED': {
        'subject': '🎉 Your Policy is Now Active',
        'body': """Dear {name},

Congratulations! Your insurance policy is now active.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 POLICY DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Policy Type: {policy_type}
Start Date: {start_date}
Coverage Amount: AUD ${coverage}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Welcome aboard!

Regards,
Insurance Platform Team"""
    }
}

def send_email(to_email, template_type, context):
    """Send email using Gmail SMTP"""
    try:
        template = EMAIL_TEMPLATES.get(template_type)
        if not template:
            return False, "Template not found"
        
        # Format body with context
        body = template['body'].format(**context)
        subject = template['subject']
        
        msg = MIMEMultipart()
        msg['From'] = os.getenv('SMTP_USER')
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(
            os.getenv('SMTP_HOST', 'smtp.gmail.com'),
            int(os.getenv('SMTP_PORT', 587))
        )
        server.starttls()
        server.login(
            os.getenv('SMTP_USER'),
            os.getenv('SMTP_PASSWORD')
        )
        server.send_message(msg)
        server.quit()
        
        print(f"Email sent to {to_email} - Type: {template_type}")
        return True, "Email sent"
    except Exception as e:
        print(f"Email error: {e}")
        return False, str(e)
    




def send_email_async(to_email, template_type, context):
    """Send email in background"""
    def _send():
        try:
            template = EMAIL_TEMPLATES.get(template_type)
            if not template:
                return
            
            body = template['body'].format(**context)
            subject = template['subject']
            
            msg = MIMEMultipart()
            msg['From'] = os.getenv('SMTP_USER')
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(os.getenv('SMTP_HOST'), int(os.getenv('SMTP_PORT')))
            server.starttls()
            server.login(os.getenv('SMTP_USER'), os.getenv('SMTP_PASSWORD'))
            server.send_message(msg)
            server.quit()
            print(f"Background email sent to {to_email}")
        except Exception as e:
            print(f"Background email error: {e}")
    
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()
    return True




def send_notification_fire_forget(user_email, user_name, notification_type, extra_context=None):
    """Send notification without waiting for response"""
    def _send():
        try:
            context = {'email': user_email, 'name': user_name or 'User'}
            if extra_context:
                context.update(extra_context)
            
            auth_header = request.headers.get('Authorization', '')
            
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

@notification_bp.route('/send', methods=['POST'])
@jwt_required()
def send_notification():
    """Send notification - returns immediately, email sent in background"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    notification_type = data.get('type')
    context = data.get('context', {})
    channels = data.get('channels', ['email', 'in_app'])
    
    results = {}
    
    # Send email in background (doesn't block response)
    if 'email' in channels and context.get('email'):
        send_email_async(context['email'], notification_type, context)
        results['email'] = {'success': True, 'message': 'Email queued (background)'}
    
    # Create in-app notification (fast, no delay)
    if 'in_app' in channels:
        title = f"{notification_type.replace('_', ' ').title()}"
        message = context.get('message', EMAIL_TEMPLATES.get(notification_type, {}).get('subject', 'Notification'))
        
        in_app = create_in_app_notification(
            user_id=user_id,
            notification_type=notification_type,
            title=title,
            message=message,
            data=context
        )
        results['in_app'] = {'success': True, 'notification_id': in_app['id']}
    
    # Return immediately without waiting for email
    return jsonify({
        'message': 'Notification queued',
        'results': results,
        'email_async': True
    }), 200


def create_in_app_notification(user_id, notification_type, title, message, data=None):
    """Create in-app notification"""
    notification = {
        'id': len(notifications_db) + 1,
        'user_id': user_id,
        'type': notification_type,
        'title': title,
        'message': message,
        'data': data or {},
        'is_read': False,
        'created_at': datetime.utcnow().isoformat(),
        'expires_at': (datetime.utcnow() + timedelta(hours=int(os.getenv('NOTIFICATION_EXPIRY_HOURS', 24)))).isoformat()
    }
    notifications_db.append(notification)
    
    # Add to user's notification list
    if user_id not in user_notifications:
        user_notifications[user_id] = []
    user_notifications[user_id].append(notification)
    
    return notification


@notification_bp.route('/inbox', methods=['GET'])
@jwt_required()
def get_inbox():
    """Get user's in-app notifications"""
    user_id = get_jwt_identity()
    
    user_nots = user_notifications.get(user_id, [])
    user_nots.sort(key=lambda x: x['created_at'], reverse=True)
    
    now = datetime.utcnow().isoformat()
    active_nots = [n for n in user_nots if n['expires_at'] > now]
    
    return jsonify({
        'notifications': active_nots,
        'unread_count': len([n for n in active_nots if not n['is_read']]),
        'total': len(active_nots)
    }), 200

@notification_bp.route('/mark-read/<int:notification_id>', methods=['PUT'])
@jwt_required()
def mark_read(notification_id):
    """Mark a notification as read"""
    user_id = get_jwt_identity()
    
    for notif in notifications_db:
        if notif['id'] == notification_id and notif['user_id'] == user_id:
            notif['is_read'] = True
            return jsonify({'message': 'Notification marked as read'}), 200
    
    return jsonify({'error': 'Notification not found'}), 404

@notification_bp.route('/mark-all-read', methods=['PUT'])
@jwt_required()
def mark_all_read():
    """Mark all notifications as read"""
    user_id = get_jwt_identity()
    
    for notif in notifications_db:
        if notif['user_id'] == user_id:
            notif['is_read'] = True
    
    return jsonify({'message': 'All notifications marked as read'}), 200

@notification_bp.route('/test-email', methods=['GET'])
def test_email():
    """Test email endpoint"""
    test_context = {
        'email': os.getenv('SMTP_USER'),
        'name': 'Test User',
        'proposal_id': 'TEST-123',
        'policy_type': 'Life Insurance',
        'premium': '150',
        'sign_url': 'http://localhost:3000/dashboard'
    }
    
    success, message = send_email(test_context['email'], 'PROPOSAL_CREATED', test_context)
    
    return jsonify({
        'test': True,
        'email_sent': success,
        'message': message
    }), 200