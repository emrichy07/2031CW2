from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from app.validators import validate_password as check_password_policy
import bleach

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Email(message="Must be a valid email address"),
        Length(min=3, max=80, message="Username must be between 3 and 80 characters")
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters")
    ])
    
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    username = StringField('Username (Email)', validators=[
        DataRequired(message="Username is required"),
        Email(message="Must be a valid email address"),
        Length(min=3, max=80, message="Username must be between 3 and 80 characters")
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters")
    ])
    
    bio = TextAreaField('Biography', validators=[
        DataRequired(message="Biography is required"),
        Length(min=10, max=500, message="Bio must be between 10 and 500 characters")
    ])
    
    role = SelectField('Role', choices=[
        ('user', 'User'),
        ('moderator', 'Moderator'),
        ('admin', 'Admin')
    ], default='user')
    
    submit = SubmitField('Register')
    
    def validate_password(self, field):
        is_valid, error_message = check_password_policy(field.data)
        if not is_valid:
            raise ValidationError(error_message)
    
    def sanitize_bio(self):
        allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
        allowed_attributes = {}  # No attributes allowed
        
        clean_bio = bleach.clean(
            self.bio.data,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True  # Remove disallowed tags entirely
        )
        
        return clean_bio


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message="Current password is required")
    ])
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="New password is required"),
        Length(min=8, message="Password must be at least 8 characters")
    ])
    
    submit = SubmitField('Change Password')
    
    def validate_new_password(self, field):
        
        is_valid, error_message = check_password_policy(field.data)
        if not is_valid:
            raise ValidationError(error_message)
        
        if field.data == self.current_password.data:
            raise ValidationError("New password must be different from current password")