import time
from auth.authentication import authenticate
from auth.rbac import get_permissions, has_permission, ROLE_DESCRIPTIONS

PASSWORD = "pass123"

print("1. Valid logins:")
for username in ["student01", "student02", "faculty01", "admin01", "guest01"]:
    user = authenticate(username, PASSWORD)
    print(f"  {username:<10} -> {user}")

print("\n2. Invalid logins (all should be None):")
cases = [
    ("student01", "wrongpass", "wrong password"),
    ("nobody",    PASSWORD,    "unknown user"),
    ("",          PASSWORD,    "empty username"),
    ("student01", "",          "empty password"),
    ("  student01  ", PASSWORD, "username with spaces (should succeed)"),
]
for username, password, label in cases:
    print(f"  {label:<40} -> {authenticate(username, password)}")

print("\n3. Session data minimization:")
user = authenticate("student01", PASSWORD)
print(f"  Keys returned: {list(user.keys())}")
print(f"  Password hash included? {'password_hash' in user}")

print("\n4. Timing check (wrong password vs unknown user should be similar):")
for username, label in [("student01", "existing user, wrong password"),
                        ("nobody", "unknown user")]:
    start = time.perf_counter()
    authenticate(username, "wrongpass")
    print(f"  {label:<32} {time.perf_counter() - start:.3f}s")

print("\n5. Permissions by role:")
for role in ["student", "faculty", "admin", "guest", "hacker"]:
    print(f"  {role:<8} {sorted(get_permissions(role))}")

print("\n6. has_permission checks:")
tests = [
    ("student", "personal_data", False),
    ("student", "own_data",      True),
    ("faculty", "academic_data", True),
    ("faculty", "personal_data", False),
    ("admin",   "personal_data", True),
    ("guest",   "academic_data", False),
    ("hacker",  "public_data",   False),
]
all_ok = True
for role, perm, expected in tests:
    result = has_permission(role, perm)
    ok = result == expected
    all_ok &= ok
    print(f"  {'PASS' if ok else 'FAIL'}  {role:<8} {perm:<14} -> {result}")
print(f"\n  All permission checks passed: {all_ok}")

print("\n7. Role descriptions (for the UI):")
for role, desc in ROLE_DESCRIPTIONS.items():
    print(f"  {role:<8} {desc}")
