from database.db import query_all
from privacy.permission_checker import Decision, TOOL_PERMISSION, TOOL_ARGS
from privacy.minimizer import ALLOWED_FIELDS


# ---------- Tool functions ----------
# Each returns full rows (SELECT *), like a real backend would.
# The minimizer, not the tool, decides which fields leave the app.
# `user` is passed in by the app from the login session, never by the LLM.

def get_public_notices(user):
    return query_all("SELECT * FROM notices ORDER BY date DESC")


def get_my_record(user):
    reg_no = user.get("linked_reg_no")
    if not reg_no:
        return []
    return query_all("SELECT * FROM students WHERE reg_no = ?", (reg_no,))


def get_student_academics(user, reg_no):
    return query_all("SELECT * FROM students WHERE reg_no = ?", (reg_no,))


def get_student_contact(user, reg_no):
    return query_all("SELECT * FROM students WHERE reg_no = ?", (reg_no,))


TOOL_FUNCTIONS = {
    "get_public_notices":    get_public_notices,
    "get_my_record":         get_my_record,
    "get_student_academics": get_student_academics,
    "get_student_contact":   get_student_contact,
}


def execute_tool(user, tool_name, decision):
    """The only way to run a tool. Requires an allowed Decision from the
    permission checker, and uses the checker's cleaned arguments."""
    if not isinstance(decision, Decision) or not decision.allowed:
        raise PermissionError("Tool execution requires an allowed permission decision")
    return TOOL_FUNCTIONS[tool_name](user, **decision.args)


# ---------- Declarations sent to the LLM (Groq / OpenAI format) ----------

_REG_NO_PARAMS = {
    "type": "object",
    "properties": {
        "reg_no": {
            "type": "string",
            "description": "Student registration number, e.g. 22BCE1001. If the user's "
                           "message contains a placeholder like [VIT_REG_NO_1], pass it exactly.",
        }
    },
    "required": ["reg_no"],
}

_NO_PARAMS = {"type": "object", "properties": {}}


def _declare(name, description, parameters):
    return {"type": "function",
            "function": {"name": name, "description": description, "parameters": parameters}}


TOOL_DECLARATIONS = [
    _declare("get_public_notices",
             "Get public university notices and announcements (exams, holidays, events).",
             _NO_PARAMS),
    _declare("get_my_record",
             "Get the logged-in user's own academic record (CGPA, attendance). "
             "Use when the user asks about 'my' marks, CGPA or attendance.",
             _NO_PARAMS),
    _declare("get_student_academics",
             "Get a specific student's academic details (CGPA, attendance) by registration number.",
             _REG_NO_PARAMS),
    _declare("get_student_contact",
             "Get a specific student's contact details (email, phone, address) by registration number.",
             _REG_NO_PARAMS),
]


# ---------- Design-time consistency check ----------
# Every tool must be defined in all four places, with matching arguments.

_declared_args = {t["function"]["name"]: sorted(t["function"]["parameters"]["properties"])
                  for t in TOOL_DECLARATIONS}
_registries = {
    "functions": TOOL_FUNCTIONS,
    "declarations": _declared_args,
    "permissions": TOOL_PERMISSION,
    "minimizer": ALLOWED_FIELDS,
    "argument list": TOOL_ARGS,
}
for _name in set().union(*_registries.values()):
    _missing = [label for label, reg in _registries.items() if _name not in reg]
    if _missing:
        raise RuntimeError(f"Design error: tool '{_name}' is missing from {_missing}")
    if _declared_args[_name] != sorted(TOOL_ARGS[_name]):
        raise RuntimeError(f"Design error: tool '{_name}' declares different arguments "
                           f"than the permission checker accepts")
