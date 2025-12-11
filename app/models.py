from app.extensions import db
from flask_login import UserMixin

class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(1000), nullable=False)    # Encrypted 

    def __init__(self, username, password, role, bio):
        self.username = username
        self.password = password
        self.role = role
        self.bio = bio
    
    def __repr__(self):
        return f'<User {self.username} - {self.role}>'