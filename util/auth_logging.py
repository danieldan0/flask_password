import os
import csv
import logging
import logging.handlers
import datetime
from flask import request

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'auth.log')
CSV_FILE = os.path.join(LOG_DIR, 'login_attempts.csv')


def init_auth_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger('auth')
    if not logger.handlers:
        handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
        fmt = '%(asctime)s %(levelname)s %(message)s'
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


def _get_client_ip():
    try:
        forwarded = request.headers.get('X-Forwarded-For', None)
        if forwarded:
            return forwarded.split(',')[0].strip()
        return request.remote_addr
    except RuntimeError:
        return None


def log_login_attempt(result: str, email: str | None = None):
    init_auth_logger()
    logger = logging.getLogger('auth')

    ts = datetime.datetime.utcnow().isoformat() + 'Z'
    ip = _get_client_ip() or ''
    email_val = email or ''

    logger.info(f"login_attempt ip={ip} result={result} email={email_val} time={ts}")

    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        write_header = not os.path.exists(CSV_FILE)
        with open(CSV_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(['timestamp_utc', 'ip', 'result', 'email'])
            writer.writerow([ts, ip, result, email_val])
    except Exception:
        logger.exception('Failed to write CSV login attempt')
