import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db, get_fernet
from app.models import User
from app.validators import validate_password, get_password_requirements

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        row = db.session.execute(
            text("SELECT * FROM user WHERE username = :username"),
            {"username": username}
        ).mappings().first()
        
        if row:
            user = db.session.get(User, row['id']) 

            if check_password_hash(user.password, password):
                fernet = get_fernet()
                decrypted_bio = fernet.decrypt(user.bio.encode()).decode()

                session['user'] = user.username
                session['role'] = user.role
                session['bio'] = decrypted_bio
                return redirect(url_for('main.dashboard'))
            else:
                flash('Login credentials are invalid, please try again')
        else:
            flash('Login credentials are invalid, Please try again')
    return render_template('login.html')

@main.route('/dashboard')
def dashboard():
    if 'user' in session:
        username = session['user']
        bio = session['bio']
        return render_template('dashboard.html', username=username, bio=bio)
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        bio = request.form['bio']
        role = request.form.get('role', 'user')

        is_valid, error_message = validate_password(password)
        print(f"[DEBUG] Password: {password}")  # Debug line
        print(f"[DEBUG] Is valid: {is_valid}")  # Debug line
        print(f"[DEBUG] Error: {error_message}")  # Debug line
        if not is_valid:
            flash(error_message, 'error')
            requirements = get_password_requirements()
            return render_template('register.html', requirements = requirements)
        
        hashed_password = generate_password_hash(password)
        fernet = get_fernet()
        encrypted_bio = fernet.encrypt(bio.encode()).decode()
        
        try:
            db.session.execute(
                text("INSERT INTO user (username, password, role, bio) VALUES (:username, :password, :role, :bio)"),
                {"username": username, "password": hashed_password, "role": role, "bio": encrypted_bio}
            )
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('main.login'))
        except Exception as e:
            db.session.rollback()
            flash('Username already exists. Please choose another.', 'error')
            requirements = get_password_requirements()
            return render_template('register.html', requirements=requirements)
    
    requirements = get_password_requirements()
    return render_template('register.html', requirements=requirements)




@main.route('/admin-panel')
def admin():
    if session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')

@main.route('/moderator')
def moderator():
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')

@main.route('/user-dashboard')
def user_dashboard():
    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        user_row = db.session.execute(
            text("SELECT * FROM user WHERE username = :username LIMIT 1"),
            {"username": username}
        ).mappings().first()

        if not user_row:
            flash('User not found', 'error')
            return render_template('change_password.html')

        user = db.session.get(User, user_row['id'])

        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            flash(error_message, 'error')
            requirements = get_password_requirements()
            return render_template('change_password.html', requirements=requirements)

        new_hashed_password = generate_password_hash(new_password)
        
        db.session.execute(
            text("UPDATE user SET password = :new_password WHERE username = :username"),
            {"new_password": new_hashed_password, "username": username}
        )
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    requirements = get_password_requirements()
    return render_template('change_password.html', requirements=requirements)


