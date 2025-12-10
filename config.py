import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY', 'demo-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
    

    SESSION_COOKIE_SECURE = False  


class ProductionConfig(Config):

    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    
    SESSION_COOKIE_SECURE = True  
    
    
    @staticmethod
    def validate():
        
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

    TESTING = True
    DEBUG = False
    SECRET_KEY = 'test-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:' 
    WTF_CSRF_ENABLED = False  


config_dict = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}
