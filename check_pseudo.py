from privacy.pseudonymizer import Pseudonymizer
from database.db import query_one

def show(label, value):
    print(f"  {label:<10} {value}")

print("1. Mask and restore free text")
ps = Pseudonymizer()
original = "I'm Rahul Sharma, reg 22BCE1001, phone 9876543210, mail rahul@gmail.com"
masked = ps.mask(original)
restored = ps.restore(masked)
show("original", original)
show("masked", masked)
show("restored", restored)
print(f"  Round trip exact: {restored == original}\n")

print("2. Same value -> same placeholder; different values -> different placeholders")
ps = Pseudonymizer()
print("  ", ps.mask("Email a@x.com, then a@x.com again, then b@x.com"), "\n")

print("3. Normalization: different spellings share one placeholder")
ps = Pseudonymizer()
print("  ", ps.mask("Reg 22bce1003 and 22BCE1003"))
print("  ", ps.mask("Phone +91 98765 43210 and 9876543210"))
print("  ", ps.mask("Aadhaar 2345 6789 0123 and 234567890123"), "\n")

print("4. Prompt and database record share placeholders (the key agent behaviour)")
ps = Pseudonymizer()
prompt_masked = ps.mask("What is the CGPA of 22BCE1001?")
record = query_one("SELECT * FROM students WHERE reg_no = ?", ("22BCE1001",))
record_masked = ps.mask_record(record)
show("prompt", prompt_masked)
print("  record:")
for k, v in record_masked.items():
    print(f"    {k:<11} {v}")
print("  (Aadhaar and PAN are masked here as a safety net; Phase 5 removes them entirely)\n")

print("5. Masking PII inside free-text fields (notice content)")
ps = Pseudonymizer()
notice = query_one("SELECT * FROM notices WHERE title = ?", ("Exam Cell Contact",))
print("  ", ps.mask_record(notice)["content"], "\n")

print("6. Restoring a simulated LLM answer")
ps = Pseudonymizer()
ps.mask_record(record)
llm_answer = "[PERSON_1] ([VIT_REG_NO_1]) has a CGPA of 8.7 and 91% attendance."
show("LLM said", llm_answer)
show("user sees", ps.restore(llm_answer))
print()

print("7. Unknown or broken placeholders are left alone (fail safe)")
show("input", "Ask [PERSON_9] or PERSON_1")
show("restored", ps.restore("Ask [PERSON_9] or PERSON_1"))
print()

print("8. Audit-safe outputs (types and counts only)")
show("types", ps.masked_types())
show("summary", ps.summary())
print()

print("9. Each request starts with an empty mapping")
fresh = Pseudonymizer()
show("restored", fresh.restore("[PERSON_1] has CGPA 8.7"))
show("summary", fresh.summary())
