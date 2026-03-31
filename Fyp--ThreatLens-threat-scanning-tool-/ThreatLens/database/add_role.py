import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "threatlens.db")
conn = sqlite3.connect(DB_PATH)

# Add role column
try:
    conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    conn.commit()
    print("[+] role column added")
except Exception as e:
    print(f"[!] {e}")

# Make first user admin (change email to yours)
email = input("Enter your admin email: ").strip()
conn.execute("UPDATE users SET role = 'admin' WHERE email = ?", (email,))
conn.commit()
print(f"[+] {email} is now admin")
conn.close()