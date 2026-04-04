from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from models import db
from routes.signing import signing_bp
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# CORS configuration - allow React frontend
CORS(app, 
     origins=["http://localhost:3000", "http://192.168.1.106:3000"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')

db.init_app(app)
jwt = JWTManager(app)

app.register_blueprint(signing_bp, url_prefix='/api/signing')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)