import re
import os

def load_password_blacklist():
    blacklist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'common_passwords.txt')

    try:
        with open(blacklist_path, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        print(f"WARNING: Password blacklist not found at {blacklist_path}")
        return set()
    
PASSWORD_BLACKLIST = load_password_blacklist()

def validate_password(password):
    if len(password) < 8:
        return False, "Password has to be atleast 8 character long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must have at least 1 uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must have at least 1 lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password has to contain at least 1 number"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        return False, "Password has to contain at least 1 special character"
    
    if password.lower() in PASSWORD_BLACKLIST:
        return False, "Pick another one, your password is too common"
        
    return True, "Valid"