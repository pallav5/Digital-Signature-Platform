from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

from routes.policy import policy_bp

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')

jwt = JWTManager(app)
CORS(app, origins=["http://localhost:3000", "http://192.168.1.106:3000"], supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

app.register_blueprint(policy_bp, url_prefix='/api/policy')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)