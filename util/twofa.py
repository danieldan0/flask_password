import pyotp
from flask import current_app


def generate_secret() -> str:
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, email: str, issuer_name: str | None = None) -> str:
    issuer = issuer_name or current_app.config.get('APP_NAME') or 'FlaskApp'
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, token: str, valid_window: int = 1) -> bool:
    try:
        totp = pyotp.TOTP(secret)
        # valid_window allows a tolerance (past/future steps)
        return totp.verify(token, valid_window=valid_window)
    except Exception:
        return False
