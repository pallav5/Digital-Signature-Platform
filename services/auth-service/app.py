from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from models import db, User, AuditLog
from routes.auth import auth_bp
from dotenv import load_dotenv
import os
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

load_dotenv()

app = Flask(__name__)

# Config - MUST be set before initializing extensions
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET')  # Required for admin panel sessions

# Initialize extensions
db.init_app(app)
jwt = JWTManager(app)

# Enable CORS for React frontend
CORS(app, origins=["http://localhost:3000", "http://192.168.1.106:3000"], supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

# Initialize Admin (remove template_mode parameter)
admin = Admin(app, name='Insurance Admin')

# Add model views (only after db is initialized)
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(AuditLog, db.session))

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)