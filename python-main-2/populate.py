# import sqlite3
# import hashlib
# import re
# from config import DATABASE

# SQL_FILE = 'SQLite_other_queries.sql'


# def hash_password(password: str) -> str:
#     return hashlib.sha256(password.encode()).hexdigest()


# def main():
#     # Read entire SQL file
#     try:
#         with open(SQL_FILE, 'r', encoding='utf-8', errors='ignore') as f:
#             content = f.read()
#     except FileNotFoundError:
#         print(f"ERROR: SQL file '{SQL_FILE}' not found.")
#         return

#     # Split content into statements by semicolon
#     parts = content.split(';')
#     non_user_statements = []
#     user_inserts = []

#     i = 0
#     while i < len(parts):
#         part = parts[i]
#         text = part.strip()
#         if not text or text.startswith('--'):
#             i += 1
#             continue

#         # Detect start of Users insert
#         if text.upper().startswith('INSERT INTO USERS'):
#             # Aggregate following parts until next INSERT
#             aggregate = text
#             j = i + 1
#             while j < len(parts) and not parts[j].strip().upper().startswith('INSERT INTO'):
#                 aggregate += ';' + parts[j]
#                 j += 1
#             user_inserts.append(aggregate)
#             i = j
#         else:
#             # Non-user statement
#             non_user_statements.append(text + ';')
#             i += 1

#     # Connect and insert non-user data
#     conn = sqlite3.connect(DATABASE)
#     cursor = conn.cursor()
#     for stmt in non_user_statements:
#         try:
#             cursor.executescript(stmt)
#         except sqlite3.Error as e:
#             print(f"Error executing statement: {e}\nStatement: {stmt}")
#     conn.commit()

#     # Process user inserts: hash passwords and insert
#     for stmt in user_inserts:
#         # Extract everything after VALUES
#         m = re.search(r"VALUES\s*(.+)", stmt, flags=re.IGNORECASE | re.DOTALL)
#         if not m:
#             continue
#         values_text = m.group(1).strip()
#         # Split individual tuples by '),'
#         tuples = re.split(r"\),", values_text)
#         for tup in tuples:
#             tup_clean = tup.strip()
#             # Remove leading 'VALUES' if present
#             if tup_clean.upper().startswith('VALUES'):
#                 tup_clean = tup_clean[len('VALUES'):].strip()
#             # Trim parentheses and trailing commas
#             tup_clean = tup_clean.lstrip('(').rstrip(')').rstrip(',')
#             parts2 = [p.strip().strip("'") for p in tup_clean.split(',')]
#             if len(parts2) < 5:
#                 continue
#             try:
#                 user_id = int(parts2[0])
#                 username = parts2[1]
#                 email = parts2[2]
#                 password_plain = parts2[3]
#                 isadmin = int(parts2[4])
#             except Exception as e:
#                 print(f"Skipping invalid user tuple '{tup_clean}': {e}")
#                 continue

#             hashed = hash_password(password_plain)
#             try:
#                 cursor.execute(
#                     'INSERT OR IGNORE INTO Users (user_id, username, email, password, isadmin) VALUES (?, ?, ?, ?, ?)',
#                     (user_id, username, email, hashed, isadmin)
#                 )
#             except sqlite3.Error as e:
#                 print(f"Error inserting user {username}: {e}")

#     conn.commit()
#     conn.close()
#     print("✅ All data inserted (with passwords hashed).")


# if __name__ == '__main__':
#     main()

# populate.py
import sqlite3
import hashlib
from config import DATABASE

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Read entire SQL file and run it as one script
    with open('SQLite_other_queries.sql', 'r', encoding='utf-8') as f:
        sql = f.read()
    cursor.executescript(sql)

    # Now hash & upsert your users separately:
    cursor.execute("SELECT user_id, password FROM Users")
    users = cursor.fetchall()
    for uid, pwd in users:
        # If it looks unhashed (length 64 hex), re‑hash & update
        if len(pwd) != 64 or any(c not in '0123456789abcdef' for c in pwd):
            new_hash = hash_password(pwd)
            cursor.execute("UPDATE Users SET password = ? WHERE user_id = ?", (new_hash, uid))

    conn.commit()
    conn.close()
    print("✅ All data inserted and passwords hashed.")

if __name__ == '__main__':
    main()
