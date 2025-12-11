from flask import request, render_template, redirect, url_for, Blueprint, flash, current_app
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db, get_fernet
from app.models import User
from app.forms import LoginForm, RegistrationForm, ChangePasswordForm
from app.decorators import role_required, admin_required

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        row = db.session.execute(
            text("SELECT * FROM user WHERE username = :username"),
            {"username": username}
        ).mappings().first()
        
        if row:
            user = db.session.get(User, row['id']) 

            if check_password_hash(user.password, password):
                login_user(user, remember=False)
                
                current_app.logger.info(
                    f"Login successful: user={user.username}, role={user.role}, "
                    f"IP={request.remote_addr}"
                )
                flash("Login successful!", 'success')
                return redirect(url_for('main.dashboard'))
            else:
                current_app.logger.warning(f"Failed login (bad pass): user={username}")
                flash('Login credentials are invalid.', 'error')
        else:
            current_app.logger.warning(f"Failed login (bad user): user={username}")
            flash('Login credentials are invalid.', 'error')
            
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    current_app.logger.info(
        f"Logout: user={current_user.username}, IP={request.remote_addr}"
    )
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data

        sanitized_bio = form.sanitize_bio()
        hashed_password = generate_password_hash(password)
        
        fernet = get_fernet()
        encrypted_bio = fernet.encrypt(sanitized_bio.encode()).decode()
        
        try:
            db.session.execute(
                text("INSERT INTO user (username, password, role, bio) VALUES (:username, :password, :role, :bio)"),
                {"username": username, "password": hashed_password, "role": role, "bio": encrypted_bio}
            )
            db.session.commit()
            
            current_app.logger.info(
                f"New user registered: username={username}, role={role}, IP={request.remote_addr}"
            )

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('main.login'))
        
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration DB Error: {e}")
            flash('Username already exists or database error.', 'error')
    
    return render_template('register.html', form=form)



@main.route('/dashboard')
@login_required
def dashboard():
    fernet = get_fernet()
    try:
        decrypted_bio = fernet.decrypt(current_user.bio.encode()).decode()
    except Exception:
        decrypted_bio = "Error: Could not decrypt biography."

    return render_template('dashboard.html', username=current_user.username, bio=decrypted_bio)

@main.route('/user-dashboard')
@login_required
@role_required('user')
def user_dashboard():
    # Access control handled by decorator
    return render_template('user_dashboard.html', username=current_user.username)

@main.route('/moderator')
@login_required
@role_required('moderator')
def moderator():
    return render_template('moderator.html')

@main.route('/admin-panel')
@login_required
@admin_required
def admin():
    return render_template('admin.html')



@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        username = current_user.username

        # Verifies the current password
        if not check_password_hash(current_user.password, current_password):
            flash('Current password is wrong', 'error')
            return render_template('change_password.html', form=form)

        new_hashed_password = generate_password_hash(new_password)
        
        try:
            db.session.execute(
                text("UPDATE user SET password = :new_password WHERE username = :username"),
                {"new_password": new_hashed_password, "username": username}
            )
            db.session.commit()

            current_app.logger.info(
                f"Password changed: user={username}, IP={request.remote_addr}"
            )
            flash('Password changed successfully', 'success')
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Password Change DB Error: {e}")
            flash("An error occurred updating the password.", 'error')

    return render_template('change_password.html', form=form)