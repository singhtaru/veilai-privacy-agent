from privacy.output_filter import filter_output
from privacy.pseudonymizer import Pseudonymizer
from database.db import query_one

# (label, LLM answer, expected: "clean" | "redacted" | "blocked" | "limitation")
CASES = [
    ("Placeholders only",
     "[PERSON_1] ([VIT_REG_NO_1]) has a CGPA of 7.85 and 76% attendance.", "clean"),
    ("Raw phone leaked",
     "You can reach them at 9876543210.", "redacted"),
    ("Raw phone with spaces",
     "Their number is 98765 43210.", "redacted"),
    ("Raw email leaked",
     "Their email is arjun.mehta@vitstudent.ac.in.", "redacted"),
    ("Placeholders plus one raw phone",
     "[PERSON_1] can be emailed at [EMAIL_ADDRESS_1] or called on 8765432109.", "redacted"),
    ("Raw reg number (LLM never saw one)",
     "The student 22BCE1003 is doing well.", "redacted"),
    ("Aadhaar appears",
     "Their Aadhaar is 4567 8901 2345.", "blocked"),
    ("PAN appears",
     "PAN on file: CDEPM3456M.", "blocked"),
    ("Normal numbers and dates",
     "CGPA 8.7, attendance 91%, exams start 17 November in Room 12345.", "clean"),
    ("Real name without placeholder (by design, not checked)",
     "Arjun Mehta has good grades.", "clean"),
    ("Obfuscated email (known limitation)",
     "Write to arjun dot mehta at vitstudent dot ac dot in.", "limitation"),
]

print("1. Filter cases")
passed = 0
for label, answer, expected in CASES:
    r = filter_output(answer)
    if r.blocked:
        outcome = "blocked"
    elif r.modified:
        outcome = "redacted"
    else:
        outcome = "clean"
    ok = outcome == expected or (expected == "limitation" and outcome == "clean")
    passed += ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print(f"        in:    {answer}")
    print(f"        out:   {r.text}")
    print(f"        leaks: {r.leaks}  blocked: {r.blocked}")
print(f"  {passed}/{len(CASES)} behaved as expected\n")

print("2. Redaction tags are never restored")
ps = Pseudonymizer()
ps.mask("Call 9876543210")                        # mapping now has [IN_PHONE_1]
r = filter_output("Call 9876543210 or [IN_PHONE_1]")
print(f"  filtered: {r.text}")
print(f"  restored: {ps.restore(r.text)}")
print("  ([IN_PHONE_1] was in the mapping so it is restored; the redacted raw value stays hidden)\n")

print("3. Why the filter runs BEFORE restoring (admin asks for a contact)")
ps = Pseudonymizer()
record = query_one("SELECT name, reg_no, email, phone FROM students WHERE reg_no = ?", ("22BCE1004",))
masked = ps.mask_record(record)
llm_answer = (f"{masked['name']} ({masked['reg_no']}) can be reached at "
              f"{masked['email']} or {masked['phone']}.")
print(f"  LLM answer:            {llm_answer}")

right = filter_output(llm_answer)
print(f"  Correct order:  filter -> leaks {right.leaks}")
print(f"                  restore -> {ps.restore(right.text)}")

wrong = filter_output(ps.restore(llm_answer))
print(f"  Wrong order:    restore then filter -> leaks {wrong.leaks}")
print(f"                  user sees -> {wrong.text}")
print("  (the wrong order would redact data the admin is allowed to see)")
