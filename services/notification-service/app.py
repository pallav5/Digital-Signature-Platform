from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

from routes.notification import notification_bp

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')

jwt = JWTManager(app)
CORS(app)

app.register_blueprint(notification_bp, url_prefix='/api/notifications')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=True)