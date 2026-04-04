from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from models import db, User, AuditLog

# Initialize admin
admin = Admin(app, name='Insurance Admin', template_mode='bootstrap4')

# Add model views
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(AuditLog, db.session))