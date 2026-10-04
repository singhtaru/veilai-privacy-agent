import bcrypt
from database.db import query_one

# Used when the username doesn't exist, so the response takes the same time
# whether or not the user exists (prevents guessing valid usernames by timing)
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt())


def authenticate(username, password):
    """Return a safe user dict if credentials are valid, otherwise None."""
    username = (username or "").strip()
    password = password or ""

    if not username or not password:
        return None

    user = query_one("SELECT * FROM users WHERE username = ?", (username,))

    if user is None:
        bcrypt.checkpw(password.encode(), _DUMMY_HASH)   # same delay as a real check
        return None

    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return None

    # Only what the rest of the app needs. The password hash never leaves this function.
    return {
        "username": user["username"],
        "role": user["role"],
        "linked_reg_no": user["linked_reg_no"],
    }
