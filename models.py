from extensions import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    is_active_account = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)

    twofa_enabled = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.String(32))

    lockout_until = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.email}>"
