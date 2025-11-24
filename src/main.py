"""
Password Manager - Secure password storage and management system
"""
import hashlib
import json
import os
import secrets
import string
from typing import Optional, Dict, List
from datetime import datetime
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2


class PasswordStrengthChecker:
    """Check password strength and provide feedback"""
    
    @staticmethod
    def check_strength(password: str) -> Dict[str, any]:
        """
        Check password strength
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with strength score and feedback
        """
        if not password:
            return {"score": 0, "strength": "empty", "feedback": ["Password cannot be empty"]}
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters")
        
        if len(password) >= 12:
            score += 1
        
        # Character variety checks
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
        
        # Determine strength level
        if score <= 2:
            strength = "weak"
        elif score <= 4:
            strength = "medium"
        else:
            strength = "strong"
        
        return {
            "score": score,
            "strength": strength,
            "feedback": feedback if feedback else ["Password is strong"]
        }


class PasswordGenerator:
    """Generate secure random passwords"""
    
    @staticmethod
    def generate(length: int = 16, use_symbols: bool = True, 
                 use_numbers: bool = True, use_uppercase: bool = True,
                 use_lowercase: bool = True) -> str:
        """
        Generate a random password
        
        Args:
            length: Length of password
            use_symbols: Include special characters
            use_numbers: Include numbers
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            
        Returns:
            Generated password
            
        Raises:
            ValueError: If invalid parameters
        """
        if length < 4:
            raise ValueError("Password length must be at least 4")
        
        if not any([use_symbols, use_numbers, use_uppercase, use_lowercase]):
            raise ValueError("At least one character type must be selected")
        
        characters = ""
        password_chars = []
        
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
        
        # Fill remaining length
        for _ in range(length - len(password_chars)):
            password_chars.append(secrets.choice(characters))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)


class Encryptor:
    """Handle encryption and decryption of passwords"""
    
    def __init__(self, master_password: str, salt: Optional[bytes] = None):
        """
        Initialize encryptor
        
        Args:
            master_password: Master password for encryption
            salt: Salt for key derivation (generated if not provided)
        """
        if not master_password:
            raise ValueError("Master password cannot be empty")
        
        self.salt = salt if salt else os.urandom(16)
        self.key = self._derive_key(master_password)
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: str) -> bytes:
        """
        Derive encryption key from password
        
        Args:
            password: Master password
            
        Returns:
            Derived key
        """
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt data
        
        Args:
            data: Plain text to encrypt
            
        Returns:
            Encrypted data as base64 string
        """
        if not data:
            raise ValueError("Data cannot be empty")
        
        encrypted = self.cipher.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt data
        
        Args:
            encrypted_data: Encrypted data as base64 string
            
        Returns:
            Decrypted plain text
            
        Raises:
            ValueError: If decryption fails
        """
        if not encrypted_data:
            raise ValueError("Encrypted data cannot be empty")
        
        try:
            decoded = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def get_salt(self) -> bytes:
        """Get the salt used for key derivation"""
        return self.salt


class PasswordEntry:
    """Represent a password entry"""
    
    def __init__(self, service: str, username: str, password: str,
                 notes: str = "", created_at: Optional[str] = None,
                 updated_at: Optional[str] = None):
        """
        Initialize password entry
        
        Args:
            service: Service name
            username: Username
            password: Password
            notes: Additional notes
            created_at: Creation timestamp
            updated_at: Update timestamp
        """
        if not service:
            raise ValueError("Service name cannot be empty")
        if not username:
            raise ValueError("Username cannot be empty")
        if not password:
            raise ValueError("Password cannot be empty")
        
        self.service = service
        self.username = username
        self.password = password
        self.notes = notes
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert entry to dictionary"""
        return {
            "service": self.service,
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'PasswordEntry':
        """Create entry from dictionary"""
        return PasswordEntry(
            service=data["service"],
            username=data["username"],
            password=data["password"],
            notes=data.get("notes", ""),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at")
        )


class PasswordManager:
    """Main password manager class"""
    
    def __init__(self, master_password: str, storage_path: str = "passwords.enc"):
        """
        Initialize password manager
        
        Args:
            master_password: Master password for encryption
            storage_path: Path to storage file
        """
        if not master_password:
            raise ValueError("Master password cannot be empty")
        
        self.storage_path = storage_path
        self.entries: Dict[str, PasswordEntry] = {}
        self.encryptor: Optional[Encryptor] = None
        self.master_password_hash = self._hash_password(master_password)
        
        # Load existing data or initialize new
        if os.path.exists(storage_path):
            self._load(master_password)
        else:
            self.encryptor = Encryptor(master_password)
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def add_entry(self, service: str, username: str, password: str,
                  notes: str = "") -> PasswordEntry:
        """
        Add a new password entry
        
        Args:
            service: Service name
            username: Username
            password: Password
            notes: Additional notes
            
        Returns:
            Created password entry
            
        Raises:
            ValueError: If entry already exists
        """
        key = f"{service}:{username}"
        
        if key in self.entries:
            raise ValueError(f"Entry for {service} with username {username} already exists")
        
        entry = PasswordEntry(service, username, password, notes)
        self.entries[key] = entry
        return entry
    
    def get_entry(self, service: str, username: str) -> Optional[PasswordEntry]:
        """
        Get a password entry
        
        Args:
            service: Service name
            username: Username
            
        Returns:
            Password entry or None if not found
        """
        key = f"{service}:{username}"
        return self.entries.get(key)
    
    def update_entry(self, service: str, username: str, 
                     new_password: Optional[str] = None,
                     new_notes: Optional[str] = None) -> PasswordEntry:
        """
        Update a password entry
        
        Args:
            service: Service name
            username: Username
            new_password: New password (optional)
            new_notes: New notes (optional)
            
        Returns:
            Updated entry
            
        Raises:
            ValueError: If entry not found
        """
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
        """
        Delete a password entry
        
        Args:
            service: Service name
            username: Username
            
        Returns:
            True if deleted, False if not found
        """
        key = f"{service}:{username}"
        
        if key in self.entries:
            del self.entries[key]
            return True
        
        return False
    
    def list_entries(self, service_filter: Optional[str] = None) -> List[PasswordEntry]:
        """
        List all password entries
        
        Args:
            service_filter: Optional filter by service name
            
        Returns:
            List of password entries
        """
        entries = list(self.entries.values())
        
        if service_filter:
            entries = [e for e in entries if service_filter.lower() in e.service.lower()]
        
        return sorted(entries, key=lambda x: x.service)
    
    def save(self) -> bool:
        """
        Save all entries to encrypted file
        
        Returns:
            True if successful
        """
        if not self.encryptor:
            return False
        
        try:
            # Prepare data
            data = {
                "salt": base64.b64encode(self.encryptor.get_salt()).decode(),
                "master_password_hash": self.master_password_hash,
                "entries": [entry.to_dict() for entry in self.entries.values()]
            }
            
            # Encrypt and save
            json_data = json.dumps(data)
            encrypted_data = self.encryptor.encrypt(json_data)
            
            with open(self.storage_path, 'w') as f:
                f.write(encrypted_data)
            
            return True
        except Exception:
            return False
    
    def _load(self, master_password: str) -> None:
        """
        Load entries from encrypted file
        
        Args:
            master_password: Master password for decryption
            
        Raises:
            ValueError: If decryption fails or password is incorrect
        """
        try:
            with open(self.storage_path, 'r') as f:
                encrypted_data = f.read()
            
            # First, try to decrypt with temporary encryptor to get salt
            temp_encryptor = Encryptor(master_password)
            
            try:
                decrypted_data = temp_encryptor.decrypt(encrypted_data)
                data = json.loads(decrypted_data)
            except Exception:
                # If that fails, we need to extract salt first
                # This is a simplified approach - in production, store salt separately
                raise ValueError("Invalid master password or corrupted data")
            
            # Verify master password
            stored_hash = data.get("master_password_hash")
            if stored_hash != self._hash_password(master_password):
                raise ValueError("Invalid master password")
            
            # Get the salt and create proper encryptor
            salt = base64.b64decode(data["salt"].encode())
            self.encryptor = Encryptor(master_password, salt)
            
            # Load entries
            self.entries = {}
            for entry_data in data.get("entries", []):
                entry = PasswordEntry.from_dict(entry_data)
                key = f"{entry.service}:{entry.username}"
                self.entries[key] = entry
                
        except FileNotFoundError:
            raise ValueError("Storage file not found")
        except json.JSONDecodeError:
            raise ValueError("Corrupted data file")
    
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """
        Change the master password
        
        Args:
            old_password: Current master password
            new_password: New master password
            
        Returns:
            True if successful
            
        Raises:
            ValueError: If old password is incorrect or new password is invalid
        """
        if not new_password:
            raise ValueError("New password cannot be empty")
        
        # Verify old password
        if self._hash_password(old_password) != self.master_password_hash:
            raise ValueError("Invalid old password")
        
        # Create new encryptor
        self.encryptor = Encryptor(new_password)
        self.master_password_hash = self._hash_password(new_password)
        
        # Save with new encryption
        return self.save()
    
    def export_to_json(self, output_path: str, include_passwords: bool = True) -> bool:
        """
        Export entries to JSON file (unencrypted)
        
        Args:
            output_path: Path to output file
            include_passwords: Whether to include passwords in export
            
        Returns:
            True if successful
        """
        try:
            entries_data = []
            for entry in self.entries.values():
                entry_dict = entry.to_dict()
                if not include_passwords:
                    entry_dict["password"] = "********"
                entries_data.append(entry_dict)
            
            with open(output_path, 'w') as f:
                json.dump(entries_data, f, indent=2)
            
            return True
        except Exception:
            return False
    
    def search_entries(self, query: str) -> List[PasswordEntry]:
        """
        Search entries by service name, username, or notes
        
        Args:
            query: Search query
            
        Returns:
            List of matching entries
        """
        if not query:
            return []
        
        query_lower = query.lower()
        results = []
        
        for entry in self.entries.values():
            if (query_lower in entry.service.lower() or
                query_lower in entry.username.lower() or
                query_lower in entry.notes.lower()):
                results.append(entry)
        
        return sorted(results, key=lambda x: x.service)


def main():
    """Main function for demonstration"""
    print("Password Manager initialized successfully!")
    print("This is a library module. Import it to use in your application.")
    
    # Example usage
    try:
        # Initialize password manager
        pm = PasswordManager("my_secure_master_password")
        
        # Generate a strong password
        generator = PasswordGenerator()
        strong_pwd = generator.generate(16)
        print(f"Generated password: {strong_pwd}")
        
        # Check password strength
        checker = PasswordStrengthChecker()
        strength = checker.check_strength(strong_pwd)
        print(f"Password strength: {strength['strength']}")
        
        # Add an entry
        entry = pm.add_entry("example.com", "user@example.com", strong_pwd, "My account")
        print(f"Added entry for {entry.service}")
        
        # Save to file
        pm.save()
        print("Passwords saved successfully!")
        
        # Clean up demo file
        if os.path.exists("passwords.enc"):
            os.remove("passwords.enc")
            
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
