from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

notification_bp = Blueprint('notification', __name__)

notifications_store = []

def send_email(to_email, subject, body):
    try:
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
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

# ── Send notification ─────────────────────────────────────
@notification_bp.route('/send', methods=['POST'])
@jwt_required()
def send_notification():
    user_id = get_jwt_identity()
    data = request.get_json()

    required = ['type', 'email', 'message']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    templates = {
        'PROPOSAL_READY': {
            'subject': 'Your Insurance Proposal is Ready',
            'body': f"Dear Customer,\n\n{data['message']}\n\n"
                    f"Please log in to review and sign your proposal.\n\n"
                    f"Insurance Platform Team"
        },
        'SIGNATURE_COMPLETE': {
            'subject': 'Document Signed Successfully',
            'body': f"Dear Customer,\n\n{data['message']}\n\n"
                    f"Your digital signature has been recorded.\n\n"
                    f"Insurance Platform Team"
        },
        'SECURITY_ALERT': {
            'subject': 'Security Alert — Immediate Action Required',
            'body': f"Dear Customer,\n\n{data['message']}\n\n"
                    f"If this was not you please contact us immediately.\n\n"
                    f"Insurance Platform Team"
        },
        'POLICY_ACTIVATED': {
            'subject': 'Your Policy is Now Active',
            'body': f"Dear Customer,\n\n{data['message']}\n\n"
                    f"Welcome aboard. Your policy is now active.\n\n"
                    f"Insurance Platform Team"
        }
    }

    template = templates.get(data['type'], {
        'subject': 'Insurance Platform Notification',
        'body': data['message']
    })

    email_sent = send_email(
        data['email'],
        template['subject'],
        template['body']
    )

    notification = {
        'id': str(len(notifications_store) + 1),
        'user_id': user_id,
        'type': data['type'],
        'email': data['email'],
        'message': data['message'],
        'email_sent': email_sent,
        'created_at': datetime.utcnow().isoformat()
    }
    notifications_store.append(notification)

    return jsonify({
        'message': 'Notification processed',
        'email_sent': email_sent,
        'notification_id': notification['id']
    }), 200

# ── Get notification history ──────────────────────────────
@notification_bp.route('/history', methods=['GET'])
@jwt_required()
def get_history():
    user_id = get_jwt_identity()
    user_notifications = [
        n for n in notifications_store
        if n['user_id'] == user_id
    ]
    return jsonify(user_notifications), 200