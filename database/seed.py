import sqlite3
import bcrypt
from config import DB_PATH

DEMO_PASSWORD = "pass123"   # demo only; documented in README

SCHEMA = """
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS students;
DROP TABLE IF EXISTS notices;
DROP TABLE IF EXISTS role_permissions;

CREATE TABLE students (
    reg_no      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT,
    phone       TEXT,
    address     TEXT,
    aadhaar     TEXT,
    pan         TEXT,
    cgpa        REAL,
    attendance  REAL
);

CREATE TABLE users (
    user_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('student', 'faculty', 'admin', 'guest')),
    linked_reg_no  TEXT REFERENCES students(reg_no)
);

CREATE TABLE notices (
    notice_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    date       TEXT NOT NULL,
    content    TEXT NOT NULL
);

CREATE TABLE role_permissions (
    role        TEXT NOT NULL,
    permission  TEXT NOT NULL,
    PRIMARY KEY (role, permission)
);

CREATE TABLE audit_logs (
    log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp          TEXT NOT NULL,
    username           TEXT NOT NULL,
    role               TEXT NOT NULL,
    tool_requested     TEXT,
    target_reg_no      TEXT,
    permission_status  TEXT,
    pii_types          TEXT,
    pii_count          INTEGER,
    masked             INTEGER,
    llm_called         INTEGER,
    output_filtered    INTEGER,
    result             TEXT
);
"""

STUDENTS = [
    # reg_no, name, email, phone, address, aadhaar, pan, cgpa, attendance
    ("22BCE1001", "Rahul Sharma",  "rahul.sharma@vitstudent.ac.in",  "9876543210",
     "12 MG Road, Bengaluru",       "2345 6789 0123", "ABCPS1234K", 8.70, 91.0),
    ("22BCE1002", "Priya Nair",    "priya.nair@vitstudent.ac.in",    "9123456780",
     "45 Anna Nagar, Chennai",      "3456 7890 1234", "BCDPN2345L", 9.10, 88.5),
    ("22BCE1003", "Arjun Mehta",   "arjun.mehta@vitstudent.ac.in",   "8765432109",
     "7 Park Street, Kolkata",      "4567 8901 2345", "CDEPM3456M", 7.85, 76.0),
    ("22BCE1004", "Sneha Reddy",   "sneha.reddy@vitstudent.ac.in",   "7654321098",
     "22 Banjara Hills, Hyderabad", "5678 9012 3456", "DEFPR4567N", 8.95, 94.5),
    ("22BCE1005", "Karan Verma",   "karan.verma@vitstudent.ac.in",   "6543210987",
     "3 Civil Lines, Jaipur",       "6789 0123 4567", "EFGPV5678P", 6.90, 68.0),
]

USERS = [
    # username, role, linked_reg_no
    ("student01", "student", "22BCE1001"),
    ("student02", "student", "22BCE1002"),
    ("faculty01", "faculty", None),
    ("admin01",   "admin",   None),
    ("guest01",   "guest",   None),
]

NOTICES = [
    ("FAT Exam Schedule Released", "2026-10-01",
     "Final assessment tests begin on 17 November. The detailed timetable is on the student portal."),
    ("Diwali Holidays", "2026-10-15",
     "The university will remain closed from 20 to 23 October for Diwali."),
    ("Exam Cell Contact", "2026-10-02",
     "For exam queries, contact the coordinator Dr. Meena Iyer at examcell.coord@vit.ac.in."),
    ("Hackathon Registrations Open", "2026-09-28",
     "Registrations for the campus hackathon close on 10 October. Teams of 2 to 4 members."),
]

ROLE_PERMISSIONS = [
    ("student", "public_data"), ("student", "own_data"),
    ("faculty", "public_data"), ("faculty", "academic_data"),
    ("admin",   "public_data"), ("admin",   "academic_data"), ("admin", "personal_data"),
    ("guest",   "public_data"),
]


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def seed():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)

        conn.executemany("INSERT INTO students VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", STUDENTS)

        conn.executemany(
            "INSERT INTO users (username, password_hash, role, linked_reg_no) VALUES (?, ?, ?, ?)",
            [(u, hash_password(DEMO_PASSWORD), role, reg) for u, role, reg in USERS],
        )

        conn.executemany("INSERT INTO notices (title, date, content) VALUES (?, ?, ?)", NOTICES)
        conn.executemany("INSERT INTO role_permissions VALUES (?, ?)", ROLE_PERMISSIONS)

        conn.commit()
        print(f"Database seeded at {DB_PATH}")
    finally:
        conn.close()


if __name__ == "__main__":
    seed()
