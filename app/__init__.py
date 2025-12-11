import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template
from werkzeug.security import generate_password_hash
from config import config_dict
from app.extensions import db, get_fernet, csrf, login_manager
from flask_login import LoginManager
from flask_talisman import Talisman

def create_app():
    app = Flask(__name__)
    
    # configuration
    env = os.environ.get('FLASK_ENV', 'development')

    if env == 'production':
        app.config.from_object(config_dict['production'])
        config_dict['production'].validate()
    elif env == 'testing':
        app.config.from_object(config_dict['testing'])
    else:
        app.config.from_object(config_dict['development'])

    # initalise extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return db.session.get(User, int(user_id))
    
    # Security headers
    if env == 'production':
        # Strict CSP for production
        csp = {
            'default-src': ["'self'"],
            'script-src': ["'self'"],
            'style-src': ["'self'"],
            'img-src': ["'self'", 'data:'],
            'font-src': ["'self'"],
            'frame-ancestors': ["'none'"]
        }
        Talisman(app, 
                 content_security_policy=csp,
                 strict_transport_security=True,
                 force_https=True)
    else:
        # Relaxing CSP to allow assets (make UI look pretty again kinda)
        csp = {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'", "https://*"],
            'style-src': ["'self'", "'unsafe-inline'", "https://*"],
            'img-src': ["'self'", 'data:', "https://*"],
            'font-src': ["'self'", "data:", "https://*"]
        }
        Talisman(app,
                 content_security_policy=csp,
                 force_https=False,
                 strict_transport_security=False)
        
    from .routes import main
    app.register_blueprint(main)

    # Error handling
    @app.errorhandler(403)
    def forbidden(error):
        app.logger.warning(f"403 Forbidden: {error}")
        return render_template('403.html'), 403
    
    @app.errorhandler(404)
    def page_not_found(error):
        app.logger.warning(f"404 Not Found: {error}")
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal error: {error}", exc_info=True)
        db.session.rollback()
        return render_template('500.html'), 500
    
    # Logging Setup
    configure_logging(app)
    
    # Database senfing
    with app.app_context():
        from .models import User
        # Resets the database after use
        db.drop_all() 
        db.create_all()

        fernet = get_fernet()

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for user_data in users:
            hashed_password = generate_password_hash(user_data["password"])
            encrypted_bio = fernet.encrypt(user_data["bio"].encode()).decode()

            user = User(
                username=user_data["username"], 
                password=hashed_password, 
                role=user_data["role"], 
                bio=encrypted_bio
            )
            db.session.add(user)
        db.session.commit()

    return app

def configure_logging(app):
    """Setting up structured logging to file and console"""
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = RotatingFileHandler(
        'logs/secureapp.log', 
        maxBytes=10*1024*1024, 
        backupCount=10
    )
    
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    if app.debug:
        file_handler.setLevel(logging.DEBUG)
        app.logger.setLevel(logging.DEBUG)
    else:
        file_handler.setLevel(logging.INFO)
        app.logger.setLevel(logging.INFO)
    
    app.logger.addHandler(file_handler)
    
    app.logger.info('='*50)
    app.logger.info('SecureApp startup')
    app.logger.info(f'Environment: {os.environ.get("FLASK_ENV", "development")}')
    app.logger.info(f'Debug mode: {app.debug}')
    app.logger.info('='*50)