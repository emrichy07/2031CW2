from functools import wraps
from flask import abort, request, current_app
from flask_login import current_user

def role_required(role):
    """
    Decorator to restrict access to specific role (Lecture 11, Section 3.1)
    
    Usage:
        @role_required('admin')
        def admin_only_route():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                # User not logged in
                current_app.logger.warning(
                    f"Unauthorized access attempt: endpoint={request.path}, "
                    f"IP={request.remote_addr}, reason=not_authenticated"
                )
                abort(403)
            
            if current_user.role != role:
                # User logged in but wrong role
                current_app.logger.warning(
                    f"Authorization denied: user={current_user.username}, "
                    f"role={current_user.role}, required_role={role}, "
                    f"endpoint={request.path}, IP={request.remote_addr}"
                )
                abort(403)
            
            # Success - log access (Lecture 13, Section 4.2)
            current_app.logger.info(
                f"Access granted: user={current_user.username}, "
                f"role={current_user.role}, endpoint={request.path}"
            )
            return f(*args, **kwargs)
        return wrapped
    return decorator


def roles_required(*roles):
    """
    Decorator to allow access to multiple roles (Lecture 11, Section 3.1)
    
    Usage:
        @roles_required('admin', 'moderator')
        def admin_or_mod_route():
            ...
    """
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
                    f"Authorization denied: user={current_user.username}, "
                    f"role={current_user.role}, required_roles={roles}, "
                    f"endpoint={request.path}, IP={request.remote_addr}"
                )
                abort(403)
            
            current_app.logger.info(
                f"Access granted: user={current_user.username}, "
                f"role={current_user.role}, endpoint={request.path}"
            )
            return f(*args, **kwargs)
        return wrapped
    return decorator


def admin_required(f):
    """
    Convenience decorator for admin-only routes (Lecture 11, Section 3.1)
    
    Usage:
        @admin_required
        def admin_route():
            ...
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            current_app.logger.warning(
                f"Admin access denied: user={getattr(current_user, 'username', 'anonymous')}, "
                f"role={getattr(current_user, 'role', 'none')}, "
                f"endpoint={request.path}, IP={request.remote_addr}"
            )
            abort(403)
        
        current_app.logger.info(
            f"Admin access granted: user={current_user.username}, "
            f"endpoint={request.path}"
        )
        return f(*args, **kwargs)
    return wrapped