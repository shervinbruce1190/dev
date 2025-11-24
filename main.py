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
ITERATIONS = 200_000  # PBKDF2 iterations
ENCODING = "utf-8"

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
    # Derive a 32-byte key for Fernet
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
    # Initialize: create salt and store verifier ciphertext for integrity
    salt = secrets.token_bytes(16)
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("salt", salt))
    conn.commit()
    return salt

def store_verifier(conn: sqlite3.Connection, fernet: Fernet):
    token = fernet.encrypt(b"vault_verifier_v1")
    # store or update
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("verifier", token))
    conn.commit()

def check_verifier(conn: sqlite3.Connection, fernet: Fernet) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key='verifier'")
    row = cur.fetchone()
    if not row:
        # First-time setup
        store_verifier(conn, fernet)
        return True
    try:
        data = fernet.decrypt(row[0])
        return data == b"vault_verifier_v1"
    except InvalidToken:
        return False

def encrypt(fernet: Fernet, plaintext: Optional[str]) -> Optional[bytes]:
    if plaintext is None or plaintext == "":
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
    service = input("Service (e.g., gmail): ").strip()
    username = input("Username: ").strip()
    password = prompt_hidden("Password: ").strip()
    notes = input("Notes (optional): ").strip()
    enc_pwd = encrypt(fernet, password)
    enc_notes = encrypt(fernet, notes) if notes else None
    try:
        conn.execute(
            "INSERT INTO entries (service, username, password, notes) VALUES (?, ?, ?, ?)",
            (service, username, enc_pwd, enc_notes),
        )
        conn.commit()
        print("Entry added.")
    except sqlite3.IntegrityError:
        print("Entry already exists. Use update.")

def cmd_get(conn, fernet):
    service = input("Service: ").strip()
    username = input("Username: ").strip()
    cur = conn.cursor()
    cur.execute(
        "SELECT password, notes FROM entries WHERE service=? AND username=?",
        (service, username),
    )
    row = cur.fetchone()
    if not row:
        print("No entry found.")
        return
    pwd = decrypt(fernet, row[0])
    notes = decrypt(fernet, row[1]) if row[1] else ""
    print(f"Password: {pwd}")
    if notes:
        print(f"Notes: {notes}")

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
    service = input("Service: ").strip()
    username = input("Username: ").strip()
    new_password = prompt_hidden("New password (leave empty to keep): ").strip()
    new_notes = input("New notes (leave empty to keep, '-' to clear): ").strip()

    cur = conn.cursor()
    cur.execute("SELECT id, password, notes FROM entries WHERE service=? AND username=?", (service, username))
    row = cur.fetchone()
    if not row:
        print("No entry found.")
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
    print("Entry updated.")

def cmd_delete(conn):
    service = input("Service: ").strip()
    username = input("Username: ").strip()
    cur = conn.cursor()
    cur.execute("SELECT id FROM entries WHERE service=? AND username=?", (service, username))
    row = cur.fetchone()
    if not row:
        print("No entry found.")
        return
    confirm = input(f"Delete {service} / {username}? (y/N): ").strip().lower()
    if confirm == "y":
        conn.execute("DELETE FROM entries WHERE id=?", (row[0],))
        conn.commit()
        print("Entry deleted.")
    else:
        print("Cancelled.")

def rotate_master_password(conn, old_fernet: Fernet):
    print("Rotate master password (re-encrypt all entries).")
    new_master = prompt_hidden("New master password: ").strip()
    confirm = prompt_hidden("Confirm new master password: ").strip()
    if new_master != confirm or not new_master:
        print("Passwords do not match or empty.")
        return
    # Generate new salt and new key
    new_salt = secrets.token_bytes(16)
    new_key = derive_key(new_master, new_salt)
    new_fernet = Fernet(new_key)

    # Re-encrypt verifier
    store_verifier(conn, new_fernet)

    # Update salt
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("salt", new_salt))

    # Re-encrypt entries
    cur = conn.cursor()
    cur.execute("SELECT id, password, notes FROM entries")
    rows = cur.fetchall()
    for entry_id, enc_pwd, enc_notes in rows:
        try:
            plain_pwd = decrypt(old_fernet, enc_pwd)
            plain_notes = decrypt(old_fernet, enc_notes) if enc_notes else None
        except InvalidToken:
            print(f"Failed to decrypt entry id {entry_id}; aborting rotation.")
            return
        new_enc_pwd = encrypt(new_fernet, plain_pwd)
        new_enc_notes = encrypt(new_fernet, plain_notes) if plain_notes else None
        conn.execute("UPDATE entries SET password=?, notes=? WHERE id=?", (new_enc_pwd, new_enc_notes, entry_id))
    conn.commit()
    print("Master password rotated successfully.")

def print_menu():
    print("\nCommands:")
    print("  add     - Add new entry")
    print("  get     - Retrieve an entry")
    print("  list    - List all entries (no passwords)")
    print("  update  - Update an entry")
    print("  delete  - Delete an entry")
    print("  rotate  - Change master password")
    print("  exit    - Quit")

def main():
    conn = connect_db()
    fernet = init_or_unlock(conn)
    print("Vault unlocked.")
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
        elif cmd == "rotate":
            rotate_master_password(conn, fernet)
            # Reinitialize with new password and salt
            fernet = init_or_unlock(conn)
            print("Vault re-unlocked.")
        elif cmd in ("exit", "quit"):
            print("Goodbye.")
            break
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()
