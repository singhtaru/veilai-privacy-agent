import re
from datetime import datetime, timedelta
from database.db import execute, query_all, query_one
from privacy.permission_checker import REG_NO_RE
from privacy.pii_detector import ALL_ENTITIES
from config import AUDIT_RETENTION_DAYS

_KNOWN_PII_TYPES = set(ALL_ENTITIES)
_VALID_PERMISSION = {"NOT_REQUIRED", "GRANTED", "DENIED"}
_VALID_RESULTS = {"SUCCESS", "DENIED", "ERROR"}
_TOOL_NAME_RE = re.compile(r"^[A-Za-z_]{1,50}$")


def _validate(trace):
    """Make sure nothing but types, decisions and identifiers reaches the log."""
    unknown = set(trace.pii_types) - _KNOWN_PII_TYPES
    if unknown:
        raise ValueError("Audit refused: pii_types must contain entity type names only")
    if trace.permission_status not in _VALID_PERMISSION:
        raise ValueError(f"Audit refused: invalid permission status '{trace.permission_status}'")
    if trace.result not in _VALID_RESULTS:
        raise ValueError(f"Audit refused: invalid result '{trace.result}'")

    tool = trace.tool_requested
    if tool is not None and not _TOOL_NAME_RE.match(tool):
        tool = "INVALID"

    target = trace.target_reg_no
    if target is not None and not REG_NO_RE.match(target):
        target = "INVALID"

    return tool, target


def log_request(user, trace):
    tool, target = _validate(trace)
    execute(
        """INSERT INTO audit_logs
           (timestamp, username, role, tool_requested, target_reg_no, permission_status,
            pii_types, pii_count, masked, llm_called, output_filtered, result)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now().isoformat(timespec="seconds"),
            user["username"],
            user["role"],
            tool,
            target,
            trace.permission_status,
            ",".join(trace.pii_types),
            trace.pii_count,
            int(trace.masked),
            int(trace.llm_called),
            int(trace.output_filtered),
            trace.result,
        ),
    )


def get_audit_logs(limit=200):
    return query_all("SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT ?", (limit,))


def purge_old_logs(days=AUDIT_RETENTION_DAYS):
    """Delete audit rows older than the retention period. Returns how many were removed."""
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    count = query_one("SELECT COUNT(*) AS n FROM audit_logs WHERE timestamp < ?", (cutoff,))["n"]
    execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,))
    return count
