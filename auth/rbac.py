from database.db import query_all

ROLE_DESCRIPTIONS = {
    "student": "Own academic record and public notices",
    "faculty": "Academic records of all students and public notices",
    "admin":   "Academic and personal records of all students, public notices",
    "guest":   "Public notices only",
}


def get_permissions(role):
    """Return the set of permissions for a role, read from the database."""
    rows = query_all("SELECT permission FROM role_permissions WHERE role = ?", (role,))
    return {r["permission"] for r in rows}


def has_permission(role, permission):
    return permission in get_permissions(role)
