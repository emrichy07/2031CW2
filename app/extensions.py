import os
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager

# Initialise extensions
db = SQLAlchemy()
csrf = CSRFProtect()

# Login manager setup
login_manager = LoginManager()
login_manager.login_view = 'main.login'
login_manager.login_message_category = 'info'

def get_fernet():
    """
    Retrieve the Fernet encryption key from environment variables.
    Used for encrypting/decrypting sensitive fields
    """
    key = os.environ.get('FERNET_KEY')
    if not key:
        raise ValueError("FERNET_KEY must be set in environment variables")
    return Fernet(key.encode())