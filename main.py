#!/usr/bin/env python3
import os
import sqlite3
import getpass
import base64
import secrets
import sys
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

DB_PATH = "vault.db"
ITERATIONS = 200_000
ENCODING = "utf-8"

# 🔹 Constants for repeated literals
PROMPT_USERNAME = "Username: "
PROMPT_SERVICE = "Service: "
PROMPT_PASSWORD = "Password: "
PROMPT_NOTES = "Notes (optional): "
MSG_NO_ENTRY = "No entry found."
MSG_ENTRY_ADDED = "Entry added."
MSG_ENTRY_UPDATED = "Entry updated."
MSG_ENTRY_DELETED = "Entry deleted."
MSG_CANCELLED = "Cancelled."
MSG_VAULT_UNLOCKED = "Vault unlocked."
MSG_GOODBYE = "Goodbye."

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    password BLOB NOT NULL,
    notes BLOB,
    UNIQUE(service, username)
);
"""

def connect_db(path=DB_PATH):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript(SCHEMA)
    return conn

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(master_password.encode(ENCODING))
    return base64.urlsafe_b64encode(key)

def get_or_init_salt_and_verifier(conn: sqlite3.Connection) -> bytes:
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key='salt'")
    row = cur.fetchone()
    if row:
        return row[0]
    salt = secrets.token_bytes(16)
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("salt", salt))
    conn.commit()
    return salt

def store_verifier(conn: sqlite3.Connection, fernet: Fernet):
    token = fernet.encrypt(b"vault_verifier_v1")
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("verifier", token))
    conn.commit()

def check_verifier(conn: sqlite3.Connection, fernet: Fernet) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key='verifier'")
    row = cur.fetchone()
    if not row:
        store_verifier(conn, fernet)
        return True
    try:
        data = fernet.decrypt(row[0])
        return data == b"vault_verifier_v1"
    except InvalidToken:
        return False

def encrypt(fernet: Fernet, plaintext: Optional[str]) -> Optional[bytes]:
    if not plaintext:
        return None
    return fernet.encrypt(plaintext.encode(ENCODING))

def decrypt(fernet: Fernet, ciphertext: Optional[bytes]) -> Optional[str]:
    if ciphertext is None:
        return None
    return fernet.decrypt(ciphertext).decode(ENCODING)

def prompt_hidden(prompt_text: str) -> str:
    try:
        return getpass.getpass(prompt_text)
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        sys.exit(1)

def init_or_unlock(conn: sqlite3.Connection) -> Fernet:
    salt = get_or_init_salt_and_verifier(conn)
    master = prompt_hidden("Master password: ")
    key = derive_key(master, salt)
    fernet = Fernet(key)
    if not check_verifier(conn, fernet):
        print("Invalid master password.")
        sys.exit(1)
    return fernet

def cmd_add(conn, fernet):
    service = input(PROMPT_SERVICE).strip()
    username = input(PROMPT_USERNAME).strip()
    password = prompt_hidden(PROMPT_PASSWORD).strip()
    notes = input(PROMPT_NOTES).strip()
    enc_pwd = encrypt(fernet, password)
    enc_notes = encrypt(fernet, notes) if notes else None
    try:
        conn.execute(
            "INSERT INTO entries (service, username, password, notes) VALUES (?, ?, ?, ?)",
            (service, username, enc_pwd, enc_notes),
        )
        conn.commit()
        print(MSG_ENTRY_ADDED)
    except sqlite3.IntegrityError:
        print("Entry already exists. Use update.")

def cmd_get(conn, fernet):
    service = input(PROMPT_SERVICE).strip()
    username = input(PROMPT_USERNAME).strip()
    cur = conn.cursor()
    cur.execute(
        "SELECT password, notes FROM entries WHERE service=? AND username=?",
        (service, username),
    )
    row = cur.fetchone()
    if not row:
        print(MSG_NO_ENTRY)
        return
    pwd = decrypt(fernet, row[0])
    notes = decrypt(fernet, row[1]) if row[1] else ""
    print(f"{PROMPT_PASSWORD}{pwd}")
    if notes:
        print(f"{PROMPT_NOTES}{notes}")

def cmd_list(conn):
    cur = conn.cursor()
    cur.execute("SELECT service, username FROM entries ORDER BY service, username")
    rows = cur.fetchall()
    if not rows:
        print("Vault is empty.")
        return
    for s, u in rows:
        print(f"- {s} / {u}")

def cmd_update(conn, fernet):
    service = input(PROMPT_SERVICE).strip()
    username = input(PROMPT_USERNAME).strip()
    new_password = prompt_hidden("New password (leave empty to keep): ").strip()
    new_notes = input("New notes (leave empty to keep, '-' to clear): ").strip()

    cur = conn.cursor()
    cur.execute("SELECT id, password, notes FROM entries WHERE service=? AND username=?", (service, username))
    row = cur.fetchone()
    if not row:
        print(MSG_NO_ENTRY)
        return
    entry_id, old_pwd, old_notes = row
    enc_pwd = encrypt(fernet, new_password) if new_password else old_pwd
    if new_notes == "-":
        enc_notes = None
    elif new_notes == "":
        enc_notes = old_notes
    else:
        enc_notes = encrypt(fernet, new_notes)

    conn.execute("UPDATE entries SET password=?, notes=? WHERE id=?", (enc_pwd, enc_notes, entry_id))
    conn.commit()
    print(MSG_ENTRY_UPDATED)

def cmd_delete(conn):
    service = input(PROMPT_SERVICE).strip()
    username = input(PROMPT_USERNAME).strip()
    cur = conn.cursor()
    cur.execute("SELECT id FROM entries WHERE service=? AND username=?", (service, username))
    row = cur.fetchone()
    if not row:
        print(MSG_NO_ENTRY)
        return
    confirm = input(f"Delete {service} / {username}? (y/N): ").strip().lower()
    if confirm == "y":
        conn.execute("DELETE FROM entries WHERE id=?", (row[0],))
        conn.commit()
        print(MSG_ENTRY_DELETED)
    else:
        print(MSG_CANCELLED)

def print_menu():
    print("\nCommands:")
    print("  add     - Add new entry")
    print("  get     - Retrieve an entry")
    print("  list    - List all entries")
    print("  update  - Update an entry")
    print("  delete  - Delete an entry")
    print("  exit    - Quit")

def main():
    conn = connect_db()
    fernet = init_or_unlock(conn)
    print(MSG_VAULT_UNLOCKED)
    while True:
        print_menu()
        cmd = input("Enter command: ").strip().lower()
        if cmd == "add":
            cmd_add(conn, fernet)
        elif cmd == "get":
            cmd_get(conn, fernet)
        elif cmd == "list":
            cmd_list(conn)
        elif cmd == "update":
            cmd_update(conn, fernet)
        elif cmd == "delete":
            cmd_delete(conn)
        elif cmd in ("exit", "quit"):
            print(MSG_GOODBYE)
            break
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()
