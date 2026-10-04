import re
from dataclasses import dataclass, field
from auth.rbac import get_permissions

REG_NO_RE = re.compile(r"^\d{2}[A-Z]{3}\d{4}$")

# Which permission each tool needs
TOOL_PERMISSION = {
    "get_public_notices":    "public_data",
    "get_my_record":         "own_data",
    "get_student_academics": "academic_data",
    "get_student_contact":   "personal_data",
}

# Which arguments each tool accepts. Anything else the LLM sends is dropped.
TOOL_ARGS = {
    "get_public_notices":    [],
    "get_my_record":         [],
    "get_student_academics": ["reg_no"],
    "get_student_contact":   ["reg_no"],
}


@dataclass
class Decision:
    allowed: bool
    reason: str
    required_permission: str | None = None
    args: dict = field(default_factory=dict)   # cleaned arguments to run the tool with


def _deny(reason, required=None, args=None):
    return Decision(False, reason, required, args or {})


def check_permission(user, tool_name, raw_args=None):
    raw_args = raw_args or {}

    # 1. Unknown tools are always denied
    if tool_name not in TOOL_PERMISSION:
        return _deny(f"Unknown tool '{tool_name}'")
    required = TOOL_PERMISSION[tool_name]

    # 2. Keep only the arguments this tool accepts, and make sure required ones exist
    args = {k: raw_args[k] for k in TOOL_ARGS[tool_name] if k in raw_args}
    for name in TOOL_ARGS[tool_name]:
        if name not in args:
            return _deny(f"Missing required argument '{name}'", required)

    # 3. Normalize and validate the registration number
    if "reg_no" in args:
        args["reg_no"] = str(args["reg_no"]).strip().upper()
        if not REG_NO_RE.match(args["reg_no"]):
            return _deny("Invalid registration number format", required, args)

    role = user.get("role")
    perms = get_permissions(role)

    # 4. Ownership rule: a student may view academics only for their own record
    if tool_name == "get_student_academics" and role == "student":
        if "own_data" in perms and args["reg_no"] == user.get("linked_reg_no"):
            return Decision(True, "Student accessing own academic record", required, args)
        return _deny("Students can only view their own academic record", required, args)

    # 5. Normal role check
    if required in perms:
        return Decision(True, f"Role '{role}' has '{required}'", required, args)
    return _deny(f"Role '{role}' lacks '{required}'", required, args)
