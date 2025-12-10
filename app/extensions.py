import os
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize DB here
db = SQLAlchemy()

# Define helper function here
def get_fernet():
    key = os.environ.get('FERNET_KEY')
    if not key:
        raise ValueError("FERNET_KEY must be set in environment variables")
    return Fernet(key.encode())