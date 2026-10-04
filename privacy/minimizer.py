SENSITIVE_FIELDS = {"aadhaar", "pan"}

# The only fields each tool may pass on, in display order
ALLOWED_FIELDS = {
    "get_public_notices":    ["title", "date", "content"],
    "get_my_record":         ["name", "reg_no", "cgpa", "attendance"],
    "get_student_academics": ["name", "reg_no", "cgpa", "attendance"],
    "get_student_contact":   ["name", "reg_no", "email", "phone", "address"],
}

# Design-time guarantee: the app refuses to start if any tool exposes Aadhaar or PAN
for _tool, _fields in ALLOWED_FIELDS.items():
    _exposed = SENSITIVE_FIELDS & set(_fields)
    if _exposed:
        raise RuntimeError(f"Design error: tool '{_tool}' would expose {_exposed}")


def minimize(tool_name, rows):
    """Return (kept_rows, dropped_field_names). Unknown tools pass nothing through."""
    if not rows:
        return [], []

    allowed = ALLOWED_FIELDS.get(tool_name)
    if allowed is None:
        return [], sorted(rows[0].keys())

    kept = [{k: row[k] for k in allowed if k in row} for row in rows]
    dropped = sorted(set(rows[0].keys()) - set(allowed))
    return kept, dropped
