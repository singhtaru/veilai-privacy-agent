from datetime import datetime, timedelta
from auth.authentication import authenticate
from agent.tools import execute_tool
from privacy.permission_checker import check_permission
from privacy.minimizer import minimize
from privacy.pseudonymizer import Pseudonymizer
from privacy.pii_detector import detect, PATTERN_ENTITIES
from tracing.trace import Trace, PASSED, MODIFIED, BLOCKED, INFO
from audit.audit_logger import log_request, get_audit_logs, purge_old_logs
from database.db import query_one, query_all, execute

ICONS = {PASSED: "✅", MODIFIED: "🟡", BLOCKED: "⛔", INFO: "ℹ️"}

# Remember where the log was, so this script can clean up its own rows
start_id = query_one("SELECT COALESCE(MAX(log_id), 0) AS m FROM audit_logs")["m"]


def tool_request(username, prompt, tool_name, llm_args):
    """Simulates one agent request that calls a tool."""
    user = authenticate(username, "pass123")
    trace, ps = Trace(), Pseudonymizer()

    masked = ps.mask(prompt)
    trace.add("Input PII scan", MODIFIED if masked != prompt else PASSED, {"sent_to_llm": masked})

    trace.llm_calls += 1     # LLM chooses a tool (simulated)
    trace.add("Tool request", INFO, {"tool": tool_name, "args_from_llm": llm_args})

    args = {k: ps.restore(str(v)) for k, v in llm_args.items()}
    decision = check_permission(user, tool_name, args)
    trace.tool_requested = tool_name
    trace.target_reg_no = decision.args.get("reg_no")

    if not decision.allowed:
        trace.permission_status = "DENIED"
        trace.add("Permission check", BLOCKED, {"reason": decision.reason})
        trace.pii_summary = ps.summary()
        trace.finish("DENIED")
        log_request(user, trace)
        return trace

    trace.permission_status = "GRANTED"
    trace.add("Permission check", PASSED, {"reason": decision.reason})

    rows = execute_tool(user, tool_name, decision)
    kept, dropped = minimize(tool_name, rows)
    trace.add("Data minimization", MODIFIED if dropped else PASSED, {"fields_removed": dropped})

    payload = [ps.mask_record(r) for r in kept]
    trace.add("Pseudonymize tool result", MODIFIED, {"sent_to_llm": payload})

    trace.llm_calls += 1     # LLM writes the answer (simulated)
    trace.add("Output privacy filter", PASSED, {"leaks_redacted": []})

    trace.pii_summary = ps.summary()
    trace.finish("SUCCESS")
    log_request(user, trace)
    return trace


def print_trace(trace):
    print(f"  Request {trace.request_id}  ({trace.duration_ms} ms, {trace.llm_calls} LLM calls)")
    for s in trace.stages:
        print(f"    {ICONS[s['status']]} {s['stage']:<26} {s['status']:<9} {s['details']}")
    print()


print("1. Granted request (faculty01 -> 22BCE1003 academics)")
print_trace(tool_request("faculty01", "What is the CGPA of 22BCE1003?",
                         "get_student_academics", {"reg_no": "[VIT_REG_NO_1]"}))

print("2. Denied request (student01 -> 22BCE1003 contact)")
print_trace(tool_request("student01", "Give me the phone number of 22BCE1003",
                         "get_student_contact", {"reg_no": "[VIT_REG_NO_1]"}))

print("3. Request with no tool (student02 says hello)")
user = authenticate("student02", "pass123")
t = Trace()
t.add("Input PII scan", PASSED, {"sent_to_llm": "Hello!"})
t.llm_calls += 1
t.add("Output privacy filter", PASSED, {"leaks_redacted": []})
t.finish("SUCCESS")
log_request(user, t)
print_trace(t)

print("4. LLM error (admin01, simulated API failure)")
user = authenticate("admin01", "pass123")
t = Trace()
t.add("Input PII scan", PASSED, {"sent_to_llm": "Any notices?"})
t.add("LLM call", BLOCKED, {"error": "simulated timeout"})
t.finish("ERROR")
log_request(user, t)
print_trace(t)

print("5. Audit log rows written by this script")
rows = query_all("SELECT * FROM audit_logs WHERE log_id > ? ORDER BY log_id", (start_id,))
for r in rows:
    print(f"  #{r['log_id']} {r['username']:<10} {r['role']:<8} tool={r['tool_requested']} "
          f"target={r['target_reg_no']} perm={r['permission_status']} "
          f"pii={r['pii_types'] or '-'}({r['pii_count']}) masked={r['masked']} "
          f"llm={r['llm_called']} result={r['result']}")
print()

print("6. Scan the audit rows for personal data values")
students = query_all("SELECT * FROM students")
known_values = [str(s[col]) for s in students
                for col in ["name", "email", "phone", "address", "aadhaar", "pan"]]
problems = []
for r in rows:
    for col, value in r.items():
        if col == "target_reg_no" or value is None:
            continue     # target_reg_no is the deliberate accountability identifier
        text = str(value)
        if any(v in text for v in known_values):
            problems.append((r["log_id"], col, "known student value"))
        if detect(text, entities=list(PATTERN_ENTITIES)):
            problems.append((r["log_id"], col, "PII pattern"))
print(f"  Problems found: {problems or 'none'}\n")

print("7. Audit guard")
bad = Trace(pii_summary={"rahul@gmail.com": 1})
try:
    log_request(authenticate("admin01", "pass123"), bad)
    print("  FAIL: a value was accepted as a PII type")
except ValueError as e:
    print(f"  PASS: {e}")

odd = Trace(tool_requested="get_student_academics", target_reg_no="[VIT_REG_NO_1]")
log_request(authenticate("faculty01", "pass123"), odd)
stored = query_one("SELECT target_reg_no FROM audit_logs ORDER BY log_id DESC LIMIT 1")
print(f"  Malformed target stored as: {stored['target_reg_no']}\n")

print("8. Retention")
old_time = (datetime.now() - timedelta(days=60)).isoformat(timespec="seconds")
execute("""INSERT INTO audit_logs (timestamp, username, role, permission_status, pii_count,
           masked, llm_called, output_filtered, result)
           VALUES (?, 'old_user', 'guest', 'NOT_REQUIRED', 0, 0, 0, 0, 'SUCCESS')""", (old_time,))
removed = purge_old_logs(30)
print(f"  Rows older than 30 days removed: {removed}")
print(f"  Recent rows still present: {len(get_audit_logs())}\n")

execute("DELETE FROM audit_logs WHERE log_id > ?", (start_id,))
print("Cleanup: test rows removed from audit_logs")
