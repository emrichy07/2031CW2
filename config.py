import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration with common settings"""
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session security settings (Part G)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # ✅ CSRF Protection (Part D - Lecture 8, Section 6.1)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # No time limit for tokens


class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = os.environ.get('DEBUG', 'True') == 'True'
    SECRET_KEY = os.environ.get('SECRET_KEY', 'demo-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
    
    # Development-specific settings
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development


class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # Production security settings
    SESSION_COOKIE_SECURE = True  # Require HTTPS in production
    
    # Validate critical settings
    @staticmethod
    def validate():
        """
        In production, secrets MUST come from environment variables.
        """
        if not os.environ.get('SECRET_KEY'):
            raise ValueError(
                "PRODUCTION ERROR: SECRET_KEY must be set as environment variable. "
                "This is a security requirement to prevent hardcoded secrets."
            )
        if not os.environ.get('DATABASE_URL'):
            raise ValueError(
                "PRODUCTION ERROR: DATABASE_URL must be set as environment variable."
            )


class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    DEBUG = False
    SECRET_KEY = 'test-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # In-memory database for tests
    WTF_CSRF_ENABLED = False  # Disable CSRF for testing


# Dictionary to map environment names to config classes
config_dict = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}