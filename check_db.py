from database.db import query_one, query_all

print("Row counts:")
for table in ["students", "users", "notices", "role_permissions", "audit_logs"]:
    count = query_one(f"SELECT COUNT(*) AS n FROM {table}")["n"]
    print(f"  {table}: {count}")

print("\nUsers:")
for u in query_all("SELECT username, role, linked_reg_no FROM users"):
    print(f"  {u['username']:<10} {u['role']:<8} linked to: {u['linked_reg_no']}")

print("\nPassword storage check:")
user = query_one("SELECT password_hash FROM users WHERE username = ?", ("student01",))
print(f"  Stored value starts with: {user['password_hash'][:7]}...")
print(f"  Plaintext stored? {user['password_hash'] == 'pass123'}")

print("\nPermissions by role:")
for role in ["student", "faculty", "admin", "guest"]:
    perms = [r["permission"] for r in query_all(
        "SELECT permission FROM role_permissions WHERE role = ?", (role,))]
    print(f"  {role:<8} {perms}")

print("\nSample student record:")
print(" ", query_one("SELECT * FROM students WHERE reg_no = ?", ("22BCE1001",)))
