import json
from agent.llm import call_llm, assistant_message
from agent.tools import TOOL_DECLARATIONS, execute_tool
from privacy.pii_detector import entity_types, detect
from privacy.pseudonymizer import Pseudonymizer, PLACEHOLDER_RE
from privacy.permission_checker import check_permission
from privacy.minimizer import minimize
from privacy.output_filter import filter_output
from tracing.trace import Trace, PASSED, MODIFIED, BLOCKED, INFO
from audit.audit_logger import log_request
from config import MAX_AGENT_STEPS, MAX_PROMPT_CHARS

ERROR_MESSAGE = "Something went wrong while processing your request. Please try again."
AUDIT_FAILURE_MESSAGE = "Your request could not be completed because it could not be logged."


def _parse_args(raw):
    """The model's arguments arrive as a JSON string. Anything malformed becomes {}."""
    try:
        args = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return args if isinstance(args, dict) else {}


def _pipeline(user, prompt, trace, ps):
    # 1. Basic input checks
    prompt = (prompt or "").strip()
    if not prompt:
        trace.add("Input check", BLOCKED, {"reason": "Empty message"})
        trace.finish("SUCCESS")
        return "Please type a question."
    if len(prompt) > MAX_PROMPT_CHARS:
        trace.add("Input check", BLOCKED, {"reason": f"Message longer than {MAX_PROMPT_CHARS} characters"})
        trace.finish("SUCCESS")
        return f"Please keep your message under {MAX_PROMPT_CHARS} characters."

    # 2. Mask PII in the user's own message
    detections = detect(prompt)
    masked_prompt = ps.mask_text(prompt, detections)
    trace.add("Input PII scan", MODIFIED if detections else PASSED,
              {"detected": entity_types(detections), "sent_to_llm": masked_prompt})

    messages = [{"role": "user", "content": masked_prompt}]
    final = None

    for _ in range(MAX_AGENT_STEPS):
        message = call_llm(messages, TOOL_DECLARATIONS)
        trace.llm_calls += 1

        if not message.tool_calls:
            final = message.content or ""
            break

        messages.append(assistant_message(message))

        for tc in message.tool_calls:
            tool_name = tc.function.name
            raw_args = _parse_args(tc.function.arguments)
            trace.add("Tool request", INFO, {"tool": tool_name, "args_from_llm": raw_args})

            # 3. Restore placeholders in the arguments, then check permission
            restored = {k: ps.restore(str(v)) for k, v in raw_args.items()}
            decision = check_permission(user, tool_name, restored)
            trace.tool_requested = tool_name
            trace.target_reg_no = decision.args.get("reg_no")

            if not decision.allowed:
                trace.permission_status = "DENIED"
                trace.add("Permission check", BLOCKED, {"reason": decision.reason})
                trace.finish("DENIED")
                return f"Access denied: {decision.reason}. No data was retrieved."

            trace.permission_status = "GRANTED"
            trace.add("Permission check", PASSED,
                      {"reason": decision.reason, "args_used": decision.args})

            # 4. Run the tool, minimize, then mask the result
            rows = execute_tool(user, tool_name, decision)
            kept, dropped = minimize(tool_name, rows)
            trace.add("Data minimization", MODIFIED if dropped else PASSED,
                      {"records": len(kept), "fields_removed": dropped})

            payload = [ps.mask_record(r) for r in kept]
            trace.add("Pseudonymize tool result", MODIFIED if payload else PASSED,
                      {"sent_to_llm": payload})

            result = {"result": payload} if payload else {"result": [], "note": "No matching record found."}
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)})

    if final is None:
        final = "I couldn't complete that request in the allowed number of steps."

    # 5. Output filter (on the placeholder version), then restore
    trace.add("LLM response", INFO, {"response": final})
    filtered = filter_output(final)
    trace.output_filtered = filtered.modified
    trace.add("Output privacy filter",
              BLOCKED if filtered.blocked else (MODIFIED if filtered.modified else PASSED),
              {"leaks_found": filtered.leaks, "answer_withheld": filtered.blocked})

    answer = ps.restore(filtered.text)
    restored_count = len(PLACEHOLDER_RE.findall(filtered.text)) - len(PLACEHOLDER_RE.findall(answer))
    trace.add("Restore placeholders", INFO, {"placeholders_restored": restored_count})

    trace.finish("SUCCESS")
    return answer


def run_agent(user, prompt):
    """Run one request through the full privacy pipeline. Returns (answer, trace)."""
    trace, ps = Trace(), Pseudonymizer()

    try:
        answer = _pipeline(user, prompt, trace, ps)
    except Exception as e:
        trace.add("Error", BLOCKED, {"error": f"{type(e).__name__}: {str(e)[:200]}"})
        trace.finish("ERROR")
        answer = ERROR_MESSAGE

    trace.pii_summary = ps.summary()

    # Fail closed: no request completes without an audit record
    try:
        log_request(user, trace)
    except Exception as e:
        trace.add("Audit log", BLOCKED, {"error": type(e).__name__})
        return AUDIT_FAILURE_MESSAGE, trace

    return answer, trace
