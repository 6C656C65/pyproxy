"""
pyproxy.monitoring.auth.py

Provides HTTP Basic Authentication setup for the monitoring Flask server,
using a single hardcoded user 'admin' with a hashed password.
"""

from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash


def create_basic_auth(password: str):
    """
    Creates and configures an HTTPBasicAuth instance with a single user.

    Args:
        password (str): The password for the 'admin' user.

    Returns:
        HTTPBasicAuth: Configured HTTPBasicAuth instance for use in Flask.
    """
    auth = HTTPBasicAuth()
    users = {"admin": generate_password_hash(password)}

    @auth.verify_password
    def verify_password(username, passwd):
        if username in users and check_password_hash(users.get(username), passwd):
            return username
        return None

    return auth
