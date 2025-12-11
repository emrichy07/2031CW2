import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration with common settings."""
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session security settings 
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = os.environ.get('DEBUG', 'True') == 'True'
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
    
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    SESSION_COOKIE_SECURE = True
    
    @staticmethod
    def validate():
        """
        Ensure critical secrets are present in production.
        """
        if not os.environ.get('SECRET_KEY'):
            raise ValueError("PRODUCTION ERROR: SECRET_KEY environment variable is missing.")
            
        if not os.environ.get('DATABASE_URL'):
            raise ValueError("PRODUCTION ERROR: DATABASE_URL environment variable is missing.")


class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    DEBUG = False
    SECRET_KEY = 'test-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  
    WTF_CSRF_ENABLED = False


# Dictionary for env names to config class
config_dict = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}