import os
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager

load_dotenv()

db = SQLAlchemy()

csrf = CSRFProtect()
login_manager = LoginManager() # <--- This is the line you are missing
login_manager.login_view = 'main.login' # Redirects users to 'login' if they aren't logged in
login_manager.login_message_category = 'info'
def get_fernet():
    key = os.environ.get('FERNET_KEY')
    if not key:
        raise ValueError("FERNET_KEY must be set in environment variables")
    return Fernet(key.encode())