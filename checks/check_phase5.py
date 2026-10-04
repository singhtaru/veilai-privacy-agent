from auth.authentication import authenticate
from privacy.permission_checker import check_permission
from privacy.minimizer import minimize, ALLOWED_FIELDS, SENSITIVE_FIELDS
from privacy.pseudonymizer import Pseudonymizer
from database.db import query_all

USERS = {u: authenticate(u, "pass123")
         for u in ["student01", "student02", "faculty01", "admin01", "guest01"]}
USERS["hacker"] = {"username": "hacker", "role": "hacker", "linked_reg_no": None}

# (user, tool, args, expected_allowed)
MATRIX = [
    # Public notices: everyone with a real role
    ("student01", "get_public_notices", {}, True),
    ("faculty01", "get_public_notices", {}, True),
    ("admin01",   "get_public_notices", {}, True),
    ("guest01",   "get_public_notices", {}, True),
    # Own record: students only
    ("student01", "get_my_record", {}, True),
    ("student02", "get_my_record", {}, True),
    ("faculty01", "get_my_record", {}, False),
    ("admin01",   "get_my_record", {}, False),
    ("guest01",   "get_my_record", {}, False),
    # Academics of 22BCE1001 (student01's own record)
    ("student01", "get_student_academics", {"reg_no": "22BCE1001"}, True),
    ("student02", "get_student_academics", {"reg_no": "22BCE1001"}, False),
    ("faculty01", "get_student_academics", {"reg_no": "22BCE1001"}, True),
    ("admin01",   "get_student_academics", {"reg_no": "22BCE1001"}, True),
    ("guest01",   "get_student_academics", {"reg_no": "22BCE1001"}, False),
    # Academics of 22BCE1003 (nobody's own record)
    ("student01", "get_student_academics", {"reg_no": "22BCE1003"}, False),
    ("faculty01", "get_student_academics", {"reg_no": "22BCE1003"}, True),
    # Contact details: admin only
    ("student01", "get_student_contact", {"reg_no": "22BCE1001"}, False),
    ("student01", "get_student_contact", {"reg_no": "22BCE1003"}, False),
    ("faculty01", "get_student_contact", {"reg_no": "22BCE1003"}, False),
    ("admin01",   "get_student_contact", {"reg_no": "22BCE1003"}, True),
    ("guest01",   "get_student_contact", {"reg_no": "22BCE1003"}, False),
]

EDGE_CASES = [
    ("admin01",   "delete_student",        {"reg_no": "22BCE1003"},     False, "unknown tool"),
    ("faculty01", "get_student_academics", {},                          False, "missing reg_no"),
    ("faculty01", "get_student_academics", {"reg_no": "[VIT_REG_NO_1]"}, False, "unresolved placeholder"),
    ("faculty01", "get_student_academics", {"reg_no": "' OR 1=1 --"},   False, "injection-style input"),
    ("faculty01", "get_student_academics", {"reg_no": " 22bce1003 "},   True,  "lowercase with spaces"),
    ("student01", "get_student_academics", {"reg_no": "22bce1001"},     True,  "own record, lowercase"),
    ("student01", "get_my_record",         {"reg_no": "22BCE1003"},     True,  "extra arg is dropped"),
    ("hacker",    "get_public_notices",    {},                          False, "unknown role"),
]

print("A. Permission matrix")
passed = 0
for username, tool, args, expected in MATRIX:
    d = check_permission(USERS[username], tool, args)
    ok = d.allowed == expected
    passed += ok
    target = args.get("reg_no", "")
    print(f"  {'PASS' if ok else 'FAIL'}  {username:<10} {tool:<22} {target:<10} "
          f"{'ALLOW' if d.allowed else 'DENY ':<5}  {d.reason}")
print(f"  {passed}/{len(MATRIX)} passed\n")

print("B. Edge cases")
edge_passed = 0
for username, tool, args, expected, label in EDGE_CASES:
    d = check_permission(USERS[username], tool, args)
    ok = d.allowed == expected
    edge_passed += ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label:<24} {'ALLOW' if d.allowed else 'DENY ':<5}  "
          f"{d.reason}  | args used: {d.args}")
print(f"  {edge_passed}/{len(EDGE_CASES)} passed\n")

print("C. Data minimization")
student_rows = query_all("SELECT * FROM students WHERE reg_no = ?", ("22BCE1003",))
notice_rows = query_all("SELECT * FROM notices")
for tool, rows in [("get_student_academics", student_rows),
                   ("get_student_contact", student_rows),
                   ("get_public_notices", notice_rows)]:
    kept, dropped = minimize(tool, rows)
    print(f"  {tool}")
    print(f"    kept fields:    {list(kept[0].keys())}")
    print(f"    dropped fields: {dropped}")
print(f"  unknown tool:  {minimize('delete_student', student_rows)}")
print(f"  empty rows:    {minimize('get_student_academics', [])}")
exposed = [t for t, f in ALLOWED_FIELDS.items() if SENSITIVE_FIELDS & set(f)]
print(f"  Tools exposing Aadhaar/PAN: {exposed or 'none'}\n")

print("D. What the LLM would receive (faculty01 asks about 22BCE1003)")
decision = check_permission(USERS["faculty01"], "get_student_academics", {"reg_no": "22BCE1003"})
rows = query_all("SELECT * FROM students WHERE reg_no = ?", (decision.args["reg_no"],))
ps = Pseudonymizer()
kept, dropped = minimize("get_student_academics", rows)
masked = [ps.mask_record(r) for r in kept]
print(f"  1. Raw row from DB:   {len(rows[0])} fields, including Aadhaar and PAN")
print(f"  2. After minimizing:  {kept[0]}")
print(f"  3. After masking:     {masked[0]}")
print(f"  4. Mapping kept in app only: {ps.summary()}")
