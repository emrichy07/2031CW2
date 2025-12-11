from functools import wraps
from flask import abort, request, current_app
from flask_login import current_user

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Checks if user is logged in
            if not current_user.is_authenticated:
                current_app.logger.warning(
                    f"Unauthorized access attempt!!: endpoint={request.path}, "
                    f"IP={request.remote_addr}, reason=not_authenticated"
                )
                abort(403)
            
            # Checks if they have right role
            if current_user.role != role:
                current_app.logger.warning(
                    f"YOU HAVE BEEN DENIED: user={current_user.username}, "
                    f"role={current_user.role}, required_role={role}, "
                    f"endpoint={request.path}, IP={request.remote_addr}"
                )
                abort(403)
            
            # Success in logging in
            current_app.logger.info(
                f"Access GRANTED: user={current_user.username}, "
                f"role={current_user.role}, endpoint={request.path}"
            )
            return f(*args, **kwargs)
        return wrapped
    return decorator


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                current_app.logger.warning(
                    f"Unauthorized access attempt: endpoint={request.path}, "
                    f"IP={request.remote_addr}, reason=not_authenticated"
                )
                abort(403)
            
            if current_user.role not in roles:
                current_app.logger.warning(
                    f"Authorization DENIED: user={current_user.username}, "
                    f"role={current_user.role}, required_roles={roles}, "
                    f"endpoint={request.path}, IP={request.remote_addr}"
                )
                abort(403)
            
            current_app.logger.info(
                f"Access GRANTED: user={current_user.username}, "
                f"role={current_user.role}, endpoint={request.path}"
            )
            return f(*args, **kwargs)
        
        return wrapped
    
    return decorator


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            current_app.logger.warning(

                f"Admin access DENIED: user={getattr(current_user, 'username', 'anonymous')}, "
                f"role={getattr(current_user, 'role', 'none')}, "
                f"endpoint={request.path}, IP={request.remote_addr}"
            )
            abort(403)
        
        current_app.logger.info(
            
            f"Admin access GRANTED: user={current_user.username}, "
            f"endpoint={request.path}"
        )
        return f(*args, **kwargs)
    return wrapped