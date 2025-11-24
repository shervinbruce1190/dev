"""
Password Manager - Secure password storage and management system
"""
import hashlib
import json
import os
import secrets
import string
import base64
from typing import Optional, Dict, List, Any
from datetime import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# -----------------------
# Utilities / Components
# -----------------------
class PasswordStrengthChecker:
    """Check password strength and provide feedback"""

    @staticmethod
    def check_strength(password: str) -> Dict[str, Any]:
        if not password:
            return {"score": 0, "strength": "empty", "feedback": ["Password cannot be empty"]}

        score = 0
        feedback: List[str] = []

        # Length checks
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters")

        if len(password) >= 12:
            score += 1

        # Character variety
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")

        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")

        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")

        if any(c in string.punctuation for c in password):
            score += 1
        else:
            feedback.append("Add special characters")

        if score <= 2:
            strength = "weak"
        elif score <= 4:
            strength = "medium"
        else:
            strength = "strong"

        return {"score": score, "strength": strength, "feedback": feedback or ["Password is strong"]}


class PasswordGenerator:
    """Generate secure random passwords"""

    @staticmethod
    def generate(length: int = 16, use_symbols: bool = True,
                 use_numbers: bool = True, use_uppercase: bool = True,
                 use_lowercase: bool = True) -> str:
        if length < 4:
            raise ValueError("Password length must be at least 4")

        if not any([use_symbols, use_numbers, use_uppercase, use_lowercase]):
            raise ValueError("At least one character type must be selected")

        characters = ""
        password_chars: List[str] = []

        if use_lowercase:
            characters += string.ascii_lowercase
            password_chars.append(secrets.choice(string.ascii_lowercase))

        if use_uppercase:
            characters += string.ascii_uppercase
            password_chars.append(secrets.choice(string.ascii_uppercase))

        if use_numbers:
            characters += string.digits
            password_chars.append(secrets.choice(string.digits))

        if use_symbols:
            characters += string.punctuation
            password_chars.append(secrets.choice(string.punctuation))

        for _ in range(length - len(password_chars)):
            password_chars.append(secrets.choice(characters))

        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)


# -----------------------
# Encryption helper
# -----------------------
class Encryptor:
    """Handle encryption and decryption of text using Fernet (key derived from password)"""

    def __init__(self, master_password: str, salt: Optional[bytes] = None, iterations: int = 100_000) -> None:
        if not master_password:
            raise ValueError("Master password cannot be empty")
        self.iterations = int(iterations)
        self.salt = salt if salt is not None else os.urandom(16)
        self._key = self._derive_key(master_password)
        self._cipher = Fernet(self._key)

    def _derive_key(self, password: str) -> bytes:
        """Derive a Fernet-compatible key (base64 urlsafe) using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.iterations,
        )
        raw = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw)

    def encrypt(self, plaintext: str) -> str:
        if plaintext is None:
            raise ValueError("Data cannot be None")
        token = self._cipher.encrypt(plaintext.encode("utf-8"))
        return base64.b64encode(token).decode("utf-8")

    def decrypt(self, encrypted_b64: str) -> str:
        if not encrypted_b64:
            raise ValueError("Encrypted data cannot be empty")
        try:
            token = base64.b64decode(encrypted_b64.encode("utf-8"))
            plaintext = self._cipher.decrypt(token)
            return plaintext.decode("utf-8")
        except Exception as e:
            # Hide low-level exception, expose a clear API-level error
            raise ValueError("Decryption failed") from e

    def get_salt(self) -> bytes:
        return self.salt


# -----------------------
# Data container
# -----------------------
class PasswordEntry:
    """Represent a password entry"""

    def __init__(self, service: str, username: str, password: str,
                 notes: str = "", created_at: Optional[str] = None,
                 updated_at: Optional[str] = None):
        if not service:
            raise ValueError("Service name cannot be empty")
        if not username:
            raise ValueError("Username cannot be empty")
        if password is None:
            raise ValueError("Password cannot be None")

        self.service = service
        self.username = username
        self.password = password
        self.notes = notes or ""
        now = datetime.now().isoformat()
        self.created_at = created_at or now
        self.updated_at = updated_at or now

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'PasswordEntry':
        return PasswordEntry(
            service=data["service"],
            username=data["username"],
            password=data["password"],
            notes=data.get("notes", ""),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at")
        )


# -----------------------
# Main manager
# -----------------------
class PasswordManager:
    """
    Main password manager class.

    File format (JSON):
    {
        "salt": "<base64 salt>",
        "iterations": <int>,
        "master_password_hash": "<sha256 hex>",
        "entries_encrypted": "<base64 ciphertext>"
    }

    The 'entries_encrypted' is a Fernet-encrypted JSON string representing a list of entry dicts.
    """

    def __init__(self, master_password: str, storage_path: str = "passwords.enc", iterations: int = 100_000):
        if not master_password:
            raise ValueError("Master password cannot be empty")
        self.storage_path = storage_path
        self.iterations = int(iterations)
        self.entries: Dict[str, PasswordEntry] = {}
        self.master_password_hash = self._hash_password(master_password)
        # If file exists -> load (will validate the master password)
        if os.path.exists(self.storage_path):
            self._load(master_password)
        else:
            # New storage: create encryptor with new salt
            self.encryptor = Encryptor(master_password, salt=None, iterations=self.iterations)

    @staticmethod
    def _hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def add_entry(self, service: str, username: str, password: str, notes: str = "") -> PasswordEntry:
        key = f"{service}:{username}"
        if key in self.entries:
            raise ValueError(f"Entry for {service} with username {username} already exists")
        entry = PasswordEntry(service, username, password, notes)
        self.entries[key] = entry
        return entry

    def get_entry(self, service: str, username: str) -> Optional[PasswordEntry]:
        return self.entries.get(f"{service}:{username}")

    def update_entry(self, service: str, username: str,
                     new_password: Optional[str] = None,
                     new_notes: Optional[str] = None) -> PasswordEntry:
        key = f"{service}:{username}"
        if key not in self.entries:
            raise ValueError(f"Entry for {service} with username {username} not found")
        entry = self.entries[key]
        if new_password is not None:
            entry.password = new_password
        if new_notes is not None:
            entry.notes = new_notes
        entry.updated_at = datetime.now().isoformat()
        return entry

    def delete_entry(self, service: str, username: str) -> bool:
        key = f"{service}:{username}"
        if key in self.entries:
            del self.entries[key]
            return True
        return False

    def list_entries(self, service_filter: Optional[str] = None) -> List[PasswordEntry]:
        results = list(self.entries.values())
        if service_filter:
            sf = service_filter.lower()
            results = [e for e in results if sf in e.service.lower()]
        return sorted(results, key=lambda x: x.service)

    def save(self) -> bool:
        """
        Save entries to storage_path. The salt and iterations are stored in plaintext so a loader can
        derive the correct key to decrypt the encrypted payload.
        """
        if not hasattr(self, "encryptor") or self.encryptor is None:
            return False

        try:
            entries_list = [entry.to_dict() for entry in self.entries.values()]
            plaintext = json.dumps({"entries": entries_list})
            encrypted_payload = self.encryptor.encrypt(plaintext)
            data = {
                "salt": base64.b64encode(self.encryptor.get_salt()).decode("utf-8"),
                "iterations": self.iterations,
                "master_password_hash": self.master_password_hash,
                "entries_encrypted": encrypted_payload
            }
            with open(self.storage_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    def _load(self, master_password: str) -> None:
        """
        Load entries from file. Requires the correct master_password.
        The salt is read from the file, used to derive the key, then the payload is decrypted.
        """
        try:
            with open(self.storage_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            raise ValueError("Storage file not found")
        except json.JSONDecodeError:
            raise ValueError("Corrupted data file")

        # Validate required fields
        for k in ("salt", "iterations", "master_password_hash", "entries_encrypted"):
            if k not in raw:
                raise ValueError("Storage file is malformed")

        salt = base64.b64decode(raw["salt"].encode("utf-8"))
        iterations = int(raw.get("iterations", self.iterations))
        stored_hash = raw["master_password_hash"]

        # Verify master password quickly by comparing hashes
        if stored_hash != self._hash_password(master_password):
            raise ValueError("Invalid master password")

        # Create encryptor with the stored salt to decrypt payload
        self.encryptor = Encryptor(master_password, salt=salt, iterations=iterations)
        self.iterations = iterations
        self.master_password_hash = stored_hash

        # Decrypt entries
        try:
            decrypted = self.encryptor.decrypt(raw["entries_encrypted"])
            data = json.loads(decrypted)
            entries_data = data.get("entries", [])
            self.entries = {}
            for ed in entries_data:
                entry = PasswordEntry.from_dict(ed)
                key = f"{entry.service}:{entry.username}"
                self.entries[key] = entry
        except Exception:
            raise ValueError("Failed to decrypt entries (wrong password or corrupted data)")

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        if not new_password:
            raise ValueError("New password cannot be empty")
        if self._hash_password(old_password) != self.master_password_hash:
            raise ValueError("Invalid old password")

        # Create new encryptor with fresh salt and re-save
        self.encryptor = Encryptor(new_password, salt=None, iterations=self.iterations)
        self.master_password_hash = self._hash_password(new_password)
        return self.save()

    def export_to_json(self, output_path: str, include_passwords: bool = True) -> bool:
        try:
            exported = []
            for entry in self.entries.values():
                d = entry.to_dict()
                if not include_passwords:
                    d["password"] = "********"
                exported.append(d)
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(exported, fh, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False

    def search_entries(self, query: str) -> List[PasswordEntry]:
        if not query:
            return []
        q = query.lower()
        matches = []
        for entry in self.entries.values():
            if (q in entry.service.lower() or q in entry.username.lower() or q in entry.notes.lower()):
                matches.append(entry)
        return sorted(matches, key=lambda x: x.service)


# -----------------------
# Demo main
# -----------------------
def main():
    print("Password Manager initialized successfully!")
    print("This is a library module. Import it to use in your application.")

    demo_path = "passwords.enc"
    try:
        pm = PasswordManager("my_secure_master_password", storage_path=demo_path)

        # Create a strong password
        strong_pwd = PasswordGenerator.generate(16)
        print(f"Generated password: {strong_pwd}")

        # Check strength
        strength = PasswordStrengthChecker.check_strength(strong_pwd)
        print(f"Password strength: {strength['strength']} ({strength['score']})")

        # Add entry and save
        pm.add_entry("example.com", "user@example.com", strong_pwd, "Demo account")
        saved = pm.save()
        print("Saved:", saved)

        # Load and read back
        pm2 = PasswordManager("my_secure_master_password", storage_path=demo_path)
        entry = pm2.get_entry("example.com", "user@example.com")
        if entry:
            print("Loaded entry:", entry.service, entry.username)

    finally:
        # cleanup demo file
        try:
            if os.path.exists(demo_path):
                os.remove(demo_path)
        except Exception:
            pass


if __name__ == "__main__":
    main()
