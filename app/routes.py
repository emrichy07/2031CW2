import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db, get_fernet
from app.models import User
from app.forms import LoginForm, RegistrationForm, ChangePasswordForm
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from app.decorators import role_required, roles_required, admin_required
from flask_login import login_user, logout_user, login_required, current_user


main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    

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
                fernet = get_fernet()
                decrypted_bio = fernet.decrypt(user.bio.encode()).decode()
                login_user(user, remember=False)
                
                # ✅ PHASE 5 - PART H: Log successful login (Lecture 13, Section 2.1)
                current_app.logger.info(
                    f"Login successful: user={user.username}, role={user.role}, "
                    f"IP={request.remote_addr}"
                )
                session['user'] = user.username
                session['role'] = user.role
                session['bio'] = decrypted_bio
                flash("Login successful!", 'success')
                return redirect(url_for('main.dashboard'))
            else:
                flash('Login credentials are invalid, please try again')
        else:
            flash('Login credentials are invalid, Please try again')
    return render_template('login.html', form=form)
@main.route('/logout')
@login_required
def logout():
    # ✅ PHASE 5 - PART H: Log logout
    current_app.logger.info(
        f"Logout: user={current_user.username}, IP={request.remote_addr}"
    )
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))

@main.route('/dashboard')
def dashboard():
    if 'user' in session:
        username = session['user']
        bio = session['bio']
        return render_template('dashboard.html', username=username, bio=bio)
    return redirect(url_for('main.login'))

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
                f"New user registered: username={username}, role={role}, "
                f"IP={request.remote_addr}"
            )

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('main.login'))
        
        except Exception as e:
            db.session.rollback()
            flash('Username already exists. Please choose another.', 'error')
    
    return render_template('register.html', form = form)


@main.route('/admin-panel')
@login_required
@admin_required
def admin():
    if session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')

@main.route('/moderator')
@login_required
@role_required('moderator')
def moderator():
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')

@main.route('/user-dashboard')
@login_required
@role_required('user')
def user_dashboard():
    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
@login_required

def change_password():
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    form = ChangePasswordForm()

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data


        user_row = db.session.execute(
            text("SELECT * FROM user WHERE username = :username LIMIT 1"),
            {"username": username}
        ).mappings().first()

        if not user_row:
            flash('User not found', 'error')
            return render_template('change_password.html', form = form)

        user = db.session.get(User, user_row['id'])

        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html', form=form)

        new_hashed_password = generate_password_hash(new_password)
        
        db.session.execute(
            text("UPDATE user SET password = :new_password WHERE username = :username"),
            {"new_password": new_hashed_password, "username": username}
        )
        db.session.commit()

        current_app.logger.info(
            f"Password changed: user={current_user.username}, IP={request.remote_addr}"
        )
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html', form = form)


