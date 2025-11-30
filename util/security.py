from wtforms import validators

def validate_strong_password(form, field):
    password = field.data
    if (len(password) < 8 or
        not any(c.islower() for c in password) or
        not any(c.isupper() for c in password) or
        not any(c.isdigit() for c in password) or
        not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for c in password)):
        raise validators.ValidationError(
            'Password must be at least 8 characters long and include '
            'uppercase, lowercase, digit, and special character.'
        )