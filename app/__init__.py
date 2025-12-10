import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template
from werkzeug.security import generate_password_hash
from config import config_dict
from app.extensions import db, get_fernet, csrf 

def create_app():
    app = Flask(__name__)
    
    env = os.environ.get('FLASK_ENV', 'development')

    if env == 'production':
        app.config.from_object(config_dict['production'])
        config_dict['production'].validate()
    elif env == 'testing':
        app.config.from_object(config_dict['testing'])
    else:
        app.config.from_object(config_dict['development'])

    db.init_app(app)
    
    csrf.init_app(app)
    
    from .routes import main
    app.register_blueprint(main)

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
    
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = RotatingFileHandler(
            'logs/secureapp.log', 
            maxBytes=10240000, 
            backupCount=10
        )
        
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('SecureApp startup')
    
    with app.app_context():
        from .models import User
        db.drop_all()
        db.create_all()

        fernet = get_fernet()

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for user_data in users:
            # Hash password
            hashed_password = generate_password_hash(user_data["password"])
            
            # Encrypt bio
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