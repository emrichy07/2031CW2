import re
import os

def load_password_blacklist():
    blacklist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'common_passwords.txt')

    try:
        with open(blacklist_path, 'r') as f:
            return set (line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()
    
PASSWORD_BLACKLIST = load_password_blacklist

def validate_password(password):
    if len(password) < 8:
        return False, "Password has to be 8 characters or more"
    if not re.search(r'[A-Z]', password):
        return False, "Password has to contain one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password has to contain a lowercase letter"
    if not re.search(r'\d',password):
        return False, "Password has to contain a number"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        return False, "Password has to contain a special characeter (!@#$%^&*()_+-=[]{}|;:,.<>?)"
    if password.lower() in PASSWORD_BLACKLIST:
        return False, "This password is too common. Please change it to a stronger password"
    return True,"Password is Valid"

def get_password_requirements():
    return [
        "At least 8 characters long",
        "Contains at least one uppercase letter (A-Z)",
        "Contains at least one lowercase letter (a-z)",
        "Contains at least one number (0-9)",
        "Contains at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)",
        "Not a commonly used password"
    ]