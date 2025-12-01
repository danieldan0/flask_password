import os

class Config:
    APP_NAME = os.environ.get("APP_NAME") or "FlaskApp"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "you-will-never-guess"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///app.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RECAPTCHA_PUBLIC_KEY = os.environ.get("RECAPTCHA_PUBLIC_KEY") or "your-public-key"
    RECAPTCHA_PRIVATE_KEY = os.environ.get("RECAPTCHA_PRIVATE_KEY") or "your-private-key"
    # Flask-Mail settings (configure via environment in production)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'localhost'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 1025)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'False').lower() in ('true', '1', 'yes')
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() in ('true', '1', 'yes')
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@example.com'
    # Failed login / lockout policy
    MAX_FAILED_LOGIN_ATTEMPTS = int(os.environ.get('MAX_FAILED_LOGIN_ATTEMPTS') or 5)
    ACCOUNT_LOCKOUT_SECONDS = int(os.environ.get('ACCOUNT_LOCKOUT_SECONDS') or 15)
    OAUTH_CREDENTIALS = {
        'google': {
            'client_id': os.environ.get('GOOGLE_CLIENT_ID') or 'your-google-client-id',
            'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET') or 'your-google-client-secret',
            'authorize_url': 'https://accounts.google.com/o/oauth2/v2/auth',
            'access_token_url': 'https://oauth2.googleapis.com/token',
            'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
            'scope': 'openid email profile',
            'server_metadata_url': 'https://accounts.google.com/.well-known/openid-configuration'
        }
    }