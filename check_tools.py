import json
import time
from auth.authentication import authenticate
from agent.tools import TOOL_DECLARATIONS, execute_tool
from privacy.permission_checker import check_permission
from privacy.minimizer import minimize
from privacy.pseudonymizer import Pseudonymizer

print("Tool declarations (what the LLM sees):")
for t in TOOL_DECLARATIONS:
    f = t["function"]
    print(f"  {f['name']:<22} args={list(f['parameters']['properties'])}")
print("  Consistency check passed (module imported without errors)\n")


# ---------- Part A: full privacy path for a tool call, no LLM ----------

def simulate(username, prompt, tool_name, llm_args):
    user = authenticate(username, "pass123")
    ps = Pseudonymizer()
    masked_prompt = ps.mask(prompt)
    print(f"[{username}] {prompt}")
    print(f"  1. Prompt sent to LLM:   {masked_prompt}")
    print(f"  2. LLM asks for:         {tool_name}({llm_args})")

    restored_args = {k: ps.restore(str(v)) for k, v in llm_args.items()}
    decision = check_permission(user, tool_name, restored_args)
    print(f"  3. Permission:           {'GRANTED' if decision.allowed else 'DENIED'} - {decision.reason}")

    if not decision.allowed:
        print("  4. Tool NOT executed. No data fetched.\n")
        return

    rows = execute_tool(user, tool_name, decision)
    if not rows:
        print("  4. Tool ran, no matching record.\n")
        return

    kept, dropped = minimize(tool_name, rows)
    payload = [ps.mask_record(r) for r in kept]
    print(f"  4. Fields removed:       {dropped}")
    print(f"  5. Tool result to LLM:   {json.dumps(payload)[:200]}")
    print(f"  6. Mapping (app only):   {ps.summary()}\n")


print("=" * 70)
print("PART A: offline simulation of the tool path")
print("=" * 70)
simulate("faculty01", "What is the CGPA of 22BCE1003?", "get_student_academics", {"reg_no": "[VIT_REG_NO_1]"})
simulate("student01", "What's my attendance?",           "get_my_record",         {})
simulate("student01", "Give me the phone number of 22BCE1003", "get_student_contact", {"reg_no": "[VIT_REG_NO_1]"})
simulate("guest01",   "Any upcoming notices?",           "get_public_notices",    {})
simulate("admin01",   "Contact details of 22BCE1004",    "get_student_contact",   {"reg_no": "[VIT_REG_NO_1]"})
simulate("faculty01", "What is the CGPA of 22BCE1099?",  "get_student_academics", {"reg_no": "[VIT_REG_NO_1]"})

print("execute_tool guard:")
student = authenticate("student01", "pass123")
denied = check_permission(student, "get_student_contact", {"reg_no": "22BCE1003"})
try:
    execute_tool(student, "get_student_contact", denied)
    print("  FAIL: tool ran with a denied decision\n")
except PermissionError as e:
    print(f"  PASS: {e}\n")


# ---------- Part B: live check that the model picks sensible tools ----------

print("=" * 70)
print("PART B: live Groq tool selection (prompts are masked before sending)")
print("=" * 70)

from groq import Groq
import config

client = Groq(api_key=config.GROQ_API_KEY)
SYSTEM = ("You are a university assistant. Use the provided tools to fetch data. "
          "Values like [PERSON_1] or [VIT_REG_NO_1] are placeholders for protected data: "
          "pass them to tools exactly as written.")

LIVE = [
    ("Any upcoming notices?",                   "get_public_notices"),
    ("What is my attendance?",                  "get_my_record"),
    ("What is the CGPA of 22BCE1003?",          "get_student_academics"),
    ("Give me the phone number of 22BCE1003",   "get_student_contact"),
    ("Hi, who are you?",                        None),
]

matches = 0
for prompt, expected in LIVE:
    masked = Pseudonymizer().mask(prompt)
    response = client.chat.completions.create(
        model=config.MODEL_NAME,
        messages=[{"role": "system", "content": SYSTEM},
                  {"role": "user", "content": masked}],
        tools=TOOL_DECLARATIONS,
        tool_choice="auto",
    )
    message = response.choices[0].message
    if message.tool_calls:
        call = message.tool_calls[0]
        name = call.function.name
        args = json.loads(call.function.arguments or "{}")
    else:
        name, args = None, {}

    ok = name == expected
    matches += ok
    print(f"  {'MATCH' if ok else 'DIFF '}  sent: {masked}")
    print(f"         tool: {name}  args: {args}")
    time.sleep(2)   # stay well within rate limits

print(f"\n  {matches}/{len(LIVE)} tool choices matched")
