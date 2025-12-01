from itsdangerous import URLSafeTimedSerializer
from flask import current_app


def _get_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])


def generate_confirmation_token(email: str) -> str:
    serializer = _get_serializer()
    return serializer.dumps(email, salt='email-confirm-salt')


def confirm_token(token: str, expiration: int = 3600) -> str | None:
    serializer = _get_serializer()
    try:
        email = serializer.loads(
            token,
            salt='email-confirm-salt',
            max_age=expiration
        )
    except Exception:
        return None
    return email


def generate_reset_token(email: str) -> str:
    serializer = _get_serializer()
    return serializer.dumps(email, salt='password-reset-salt')


def confirm_reset_token(token: str, expiration: int = 3600) -> str | None:
    serializer = _get_serializer()
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
    except Exception:
        return None
    return email
