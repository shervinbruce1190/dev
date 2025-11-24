# main.py
"""
Simple Password Manager (stdlib-only)

Features:
- Add / get / delete / list credential entries (service + username)
- Encrypts stored passwords with a key derived from a master password (PBKDF2)
- Persists data to a JSON file (salt + base64 ciphertexts)
- No external dependencies

Usage (example):
    pm = PasswordManager("vault.json", master_password="my-secret")
    pm.add("gmail", "user1", "pass1")
    pm.get("gmail", "user1")
"""

from __future__ import annotations
import json
import os
import base64
import hashlib
import secrets
from typing import Optional, Dict, Tuple, List

_DEFAULT_ITERATIONS = 100_000
_SALT_BYTES = 16
_KEY_BYTES = 32  # length of derived key in bytes


class PasswordManager:
    """
    A small password manager that stores encrypted passwords in a JSON file.

    Storage format (JSON):
    {
        "salt": "<base64 salt>",
        "entries": {
            "<service>|<username>": "<base64 ciphertext>",
            ...
        },
        "iterations": <int>
    }
    """

    def __init__(self, path: str, master_password: str, iterations: int = _DEFAULT_ITERATIONS) -> None:
        if not master_password:
            raise ValueError("master_password must be a non-empty string")
        self.path = path
        self.master_password = master_password
        self.iterations = int(iterations)
        # load or initialize storage
        self._data = {"salt": None, "entries": {}, "iterations": self.iterations}
        if os.path.exists(self.path):
            self._load()
        else:
            # create new salt and save
            salt = secrets.token_bytes(_SALT_BYTES)
            self._data["salt"] = base64.b64encode(salt).decode("utf-8")
            self._save()

    # ------------------------
    # low-level crypto helpers
    # ------------------------
    def _salt_bytes(self) -> bytes:
        s = self._data["salt"]
        if s is None:
            raise RuntimeError("Salt missing from storage")
        return base64.b64decode(s.encode("utf-8"))

    def _derive_key(self) -> bytes:
        """Derive a symmetric key from the master password and salt (PBKDF2-HMAC-SHA256)."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            self.master_password.encode("utf-8"),
            self._salt_bytes(),
            self.iterations,
            dklen=_KEY_BYTES,
        )

    @staticmethod
    def _xor_stream(data: bytes, key: bytes) -> bytes:
        """
        Simple XOR stream cipher (key repeated). Not cryptographically equivalent to AES,
        but acceptable for demonstration. Replace with modern crypto for production.
        """
        if len(key) == 0:
            raise ValueError("key must be non-empty bytes")
        out = bytearray(len(data))
        key_len = len(key)
        for i, b in enumerate(data):
            out[i] = b ^ key[i % key_len]
        return bytes(out)

    def _encrypt(self, plaintext: str) -> str:
        key = self._derive_key()
        pt_bytes = plaintext.encode("utf-8")
        ct = self._xor_stream(pt_bytes, key)
        return base64.b64encode(ct).decode("utf-8")

    def _decrypt(self, ciphertext_b64: str) -> Optional[str]:
        try:
            key = self._derive_key()
            ct = base64.b64decode(ciphertext_b64.encode("utf-8"))
            pt_bytes = self._xor_stream(ct, key)
            return pt_bytes.decode("utf-8")
        except Exception:
            # If decryption fails due to wrong password or malformed data, return None
            return None

    # ------------------------
    # storage helpers
    # ------------------------
    def _save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, ensure_ascii=False, indent=2)

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Validate required keys
        if "salt" not in data or "entries" not in data or "iterations" not in data:
            raise ValueError("Storage file is malformed")
        self._data = data
        # keep iterations consistent
        self.iterations = int(self._data.get("iterations", self.iterations))

    # ------------------------
    # public API
    # ------------------------
    def add(self, service: str, username: str, password: str) -> bool:
        """
        Add a new entry. Returns False if the (service, username) already exists.
        """
        if not service or not username:
            raise ValueError("service and username must be non-empty")
        key = self._entry_key(service, username)
        if key in self._data["entries"]:
            return False
        self._data["entries"][key] = self._encrypt(password)
        self._save()
        return True

    def get(self, service: str, username: str) -> Optional[str]:
        """
        Retrieve the plaintext password for (service, username).
        Returns None if entry does not exist or decryption fails (e.g., wrong master password).
        """
        key = self._entry_key(service, username)
        ct_b64 = self._data["entries"].get(key)
        if ct_b64 is None:
            return None
        return self._decrypt(ct_b64)

    def delete(self, service: str, username: str) -> bool:
        """
        Delete an entry. Returns True if deleted, False if entry doesn't exist.
        """
        key = self._entry_key(service, username)
        if key in self._data["entries"]:
            del self._data["entries"][key]
            self._save()
            return True
        return False

    def list_entries(self) -> List[Tuple[str, str]]:
        """
        Return a list of (service, username) tuples stored in the vault.
        """
        return [tuple(k.split("|", 1)) for k in self._data["entries"].keys()]

    @staticmethod
    def _entry_key(service: str, username: str) -> str:
        return f"{service}|{username}"
