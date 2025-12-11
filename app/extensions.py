import os
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager

# Initialise extensions
db = SQLAlchemy()
csrf = CSRFProtect()

#Login manager setup
login_manager = LoginManager()
login_manager.login_view = 'main.login'
login_manager.login_message_category = 'info'

def get_fernet():
    
    key = os.environ.get('FERNET_KEY')

    if not key:
        raise ValueError("FERNET_KEY has to be set in environment variables")
    return Fernet(key.encode())