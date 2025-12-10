import os
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect

load_dotenv()

db = SQLAlchemy()

csrf = CSRFProtect()

def get_fernet():
    key = os.environ.get('FERNET_KEY')
    if not key:
        raise ValueError("FERNET_KEY must be set in environment variables")
    return Fernet(key.encode())