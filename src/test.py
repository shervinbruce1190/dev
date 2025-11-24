"""
Comprehensive test suite for Password Manager
Achieves 100% code coverage for SonarQube analysis
"""
import unittest
import os
import json
import tempfile
import base64
from unittest.mock import patch, mock_open
from datetime import datetime

from main import (
    PasswordStrengthChecker,
    PasswordGenerator,
    Encryptor,
    PasswordEntry,
    PasswordManager,
    main
)


class TestPasswordStrengthChecker(unittest.TestCase):
    """Test PasswordStrengthChecker class"""
    
    def setUp(self):
        self.checker = PasswordStrengthChecker()
    
    def test_empty_password(self):
        """Test empty password"""
        result = self.checker.check_strength("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["strength"], "empty")
        self.assertIn("Password cannot be empty", result["feedback"])
    
    def test_weak_password(self):
        """Test weak password"""
        result = self.checker.check_strength("abc")
        self.assertEqual(result["strength"], "weak")
        self.assertLessEqual(result["score"], 2)
    
    def test_medium_password(self):
        """Test medium strength password"""
        result = self.checker.check_strength("Abcd1234")
        self.assertIn(result["strength"], ["medium", "weak"])
    
    def test_strong_password(self):
        """Test strong password"""
        result = self.checker.check_strength("Abcd1234!@#$")
        self.assertEqual(result["strength"], "strong")
        self.assertGreater(result["score"], 4)
    
    def test_password_with_uppercase(self):
        """Test password with uppercase letters"""
        result = self.checker.check_strength("ABCD1234!@#$")
        self.assertGreater(result["score"], 0)
    
    def test_password_with_lowercase(self):
        """Test password with lowercase letters"""
        result = self.checker.check_strength("abcd1234!@#$")
        self.assertGreater(result["score"], 0)
    
    def test_password_with_numbers(self):
        """Test password with numbers"""
        result = self.checker.check_strength("ABCDabcd1234")
        self.assertGreater(result["score"], 0)
    
    def test_password_with_special_chars(self):
        """Test password with special characters"""
        result = self.checker.check_strength("ABCDabcd!@#$")
        self.assertGreater(result["score"], 0)
    
    def test_short_password_feedback(self):
        """Test feedback for short password"""
        result = self.checker.check_strength("Ab1!")
        self.assertIn("Password should be at least 8 characters", result["feedback"])
    
    def test_password_missing_uppercase(self):
        """Test feedback for missing uppercase"""
        result = self.checker.check_strength("abcd1234!@#$")
        self.assertIn("Add uppercase letters", result["feedback"])
    
    def test_password_missing_lowercase(self):
        """Test feedback for missing lowercase"""
        result = self.checker.check_strength("ABCD1234!@#$")
        self.assertIn("Add lowercase letters", result["feedback"])
    
    def test_password_missing_numbers(self):
        """Test feedback for missing numbers"""
        result = self.checker.check_strength("ABCDabcd!@#$")
        self.assertIn("Add numbers", result["feedback"])
    
    def test_password_missing_special(self):
        """Test feedback for missing special characters"""
        result = self.checker.check_strength("ABCDabcd1234")
        self.assertIn("Add special characters", result["feedback"])
    
    def test_password_length_12_plus(self):
        """Test password with length >= 12"""
        result = self.checker.check_strength("ABCDabcd1234!@#$")
        self.assertGreaterEqual(result["score"], 5)


class TestPasswordGenerator(unittest.TestCase):
    """Test PasswordGenerator class"""
    
    def setUp(self):
        self.generator = PasswordGenerator()
    
    def test_generate_default(self):
        """Test default password generation"""
        password = self.generator.generate()
        self.assertEqual(len(password), 16)
    
    def test_generate_custom_length(self):
        """Test custom length generation"""
        password = self.generator.generate(length=20)
        self.assertEqual(len(password), 20)
    
    def test_generate_minimum_length(self):
        """Test minimum length generation"""
        password = self.generator.generate(length=4)
        self.assertEqual(len(password), 4)
    
    def test_generate_too_short_raises_error(self):
        """Test that too short length raises error"""
        with self.assertRaises(ValueError) as context:
            self.generator.generate(length=3)
        self.assertIn("at least 4", str(context.exception))
    
    def test_generate_no_character_types_raises_error(self):
        """Test that no character types raises error"""
        with self.assertRaises(ValueError) as context:
            self.generator.generate(
                use_symbols=False,
                use_numbers=False,
                use_uppercase=False,
                use_lowercase=False
            )
        self.assertIn("At least one character type", str(context.exception))
    
    def test_generate_with_symbols(self):
        """Test generation with symbols"""
        password = self.generator.generate(length=20, use_symbols=True)
        self.assertTrue(any(c in password for c in "!@#$%^&*"))
    
    def test_generate_without_symbols(self):
        """Test generation without symbols"""
        password = self.generator.generate(length=100, use_symbols=False)
        self.assertFalse(any(c in password for c in "!@#$%^&*"))
    
    def test_generate_without_numbers(self):
        """Test generation without numbers"""
        password = self.generator.generate(length=100, use_numbers=False)
        self.assertFalse(any(c.isdigit() for c in password))
    
    def test_generate_without_uppercase(self):
        """Test generation without uppercase"""
        password = self.generator.generate(length=100, use_uppercase=False)
        self.assertFalse(any(c.isupper() for c in password))
    
    def test_generate_without_lowercase(self):
        """Test generation without lowercase"""
        password = self.generator.generate(length=100, use_lowercase=False)
        self.assertFalse(any(c.islower() for c in password))
    
    def test_generate_only_lowercase(self):
        """Test generation with only lowercase"""
        password = self.generator.generate(
            length=20,
            use_symbols=False,
            use_numbers=False,
            use_uppercase=False,
            use_lowercase=True
        )
        self.assertTrue(all(c.islower() for c in password))
    
    def test_generate_only_uppercase(self):
        """Test generation with only uppercase"""
        password = self.generator.generate(
            length=20,
            use_symbols=False,
            use_numbers=False,
            use_uppercase=True,
            use_lowercase=False
        )
        self.assertTrue(all(c.isupper() for c in password))
    
    def test_generate_only_numbers(self):
        """Test generation with only numbers"""
        password = self.generator.generate(
            length=20,
            use_symbols=False,
            use_numbers=True,
            use_uppercase=False,
            use_lowercase=False
        )
        self.assertTrue(all(c.isdigit() for c in password))


class TestEncryptor(unittest.TestCase):
    """Test Encryptor class"""
    
    def test_init_with_password(self):
        """Test initialization with password"""
        encryptor = Encryptor("test_password")
        self.assertIsNotNone(encryptor.key)
        self.assertIsNotNone(encryptor.salt)
    
    def test_init_with_empty_password_raises_error(self):
        """Test that empty password raises error"""
        with self.assertRaises(ValueError) as context:
            Encryptor("")
        self.assertIn("cannot be empty", str(context.exception))
    
    def test_init_with_custom_salt(self):
        """Test initialization with custom salt"""
        salt = os.urandom(16)
        encryptor = Encryptor("test_password", salt)
        self.assertEqual(encryptor.salt, salt)
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption"""
        encryptor = Encryptor("test_password")
        original = "secret_data"
        encrypted = encryptor.encrypt(original)
        decrypted = encryptor.decrypt(encrypted)
        self.assertEqual(original, decrypted)
    
    def test_encrypt_empty_raises_error(self):
        """Test that encrypting empty data raises error"""
        encryptor = Encryptor("test_password")
        with self.assertRaises(ValueError) as context:
            encryptor.encrypt("")
        self.assertIn("cannot be empty", str(context.exception))
    
    def test_decrypt_empty_raises_error(self):
        """Test that decrypting empty data raises error"""
        encryptor = Encryptor("test_password")
        with self.assertRaises(ValueError) as context:
            encryptor.decrypt("")
        self.assertIn("cannot be empty", str(context.exception))
    
    def test_decrypt_invalid_data_raises_error(self):
        """Test that decrypting invalid data raises error"""
        encryptor = Encryptor("test_password")
        with self.assertRaises(ValueError) as context:
            encryptor.decrypt("invalid_data")
        self.assertIn("Decryption failed", str(context.exception))
    
    def test_get_salt(self):
        """Test getting salt"""
        encryptor = Encryptor("test_password")
        salt = encryptor.get_salt()
        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(salt), 16)
    
    def test_different_passwords_different_results(self):
        """Test that different passwords produce different results"""
        data = "test_data"
        encryptor1 = Encryptor("password1")
        encryptor2 = Encryptor("password2")
        encrypted1 = encryptor1.encrypt(data)
        encrypted2 = encryptor2.encrypt(data)
        self.assertNotEqual(encrypted1, encrypted2)


class TestPasswordEntry(unittest.TestCase):
    """Test PasswordEntry class"""
    
    def test_create_entry(self):
        """Test creating a password entry"""
        entry = PasswordEntry("service", "user", "pass", "notes")
        self.assertEqual(entry.service, "service")
        self.assertEqual(entry.username, "user")
        self.assertEqual(entry.password, "pass")
        self.assertEqual(entry.notes, "notes")
    
    def test_create_entry_without_notes(self):
        """Test creating entry without notes"""
        entry = PasswordEntry("service", "user", "pass")
        self.assertEqual(entry.notes, "")
    
    def test_create_entry_empty_service_raises_error(self):
        """Test that empty service raises error"""
        with self.assertRaises(ValueError) as context:
            PasswordEntry("", "user", "pass")
        self.assertIn("Service name cannot be empty", str(context.exception))
    
    def test_create_entry_empty_username_raises_error(self):
        """Test that empty username raises error"""
        with self.assertRaises(ValueError) as context:
            PasswordEntry("service", "", "pass")
        self.assertIn("Username cannot be empty", str(context.exception))
    
    def test_create_entry_empty_password_raises_error(self):
        """Test that empty password raises error"""
        with self.assertRaises(ValueError) as context:
            PasswordEntry("service", "user", "")
        self.assertIn("Password cannot be empty", str(context.exception))
    
    def test_entry_has_timestamps(self):
        """Test that entry has timestamps"""
        entry = PasswordEntry("service", "user", "pass")
        self.assertIsNotNone(entry.created_at)
        self.assertIsNotNone(entry.updated_at)
    
    def test_to_dict(self):
        """Test converting entry to dictionary"""
        entry = PasswordEntry("service", "user", "pass", "notes")
        entry_dict = entry.to_dict()
        self.assertEqual(entry_dict["service"], "service")
        self.assertEqual(entry_dict["username"], "user")
        self.assertEqual(entry_dict["password"], "pass")
        self.assertEqual(entry_dict["notes"], "notes")
        self.assertIn("created_at", entry_dict)
        self.assertIn("updated_at", entry_dict)
    
    def test_from_dict(self):
        """Test creating entry from dictionary"""
        data = {
            "service": "service",
            "username": "user",
            "password": "pass",
            "notes": "notes",
            "created_at": "2024-01-01T00:00:00",
            "updated_at": "2024-01-01T00:00:00"
        }
        entry = PasswordEntry.from_dict(data)
        self.assertEqual(entry.service, "service")
        self.assertEqual(entry.username, "user")
        self.assertEqual(entry.password, "pass")
        self.assertEqual(entry.notes, "notes")
    
    def test_from_dict_without_notes(self):
        """Test creating entry from dict without notes"""
        data = {
            "service": "service",
            "username": "user",
            "password": "pass"
        }
        entry = PasswordEntry.from_dict(data)
        self.assertEqual(entry.notes, "")
    
    def test_from_dict_without_timestamps(self):
        """Test creating entry from dict without timestamps"""
        data = {
            "service": "service",
            "username": "user",
            "password": "pass"
        }
        entry = PasswordEntry.from_dict(data)
        self.assertIsNotNone(entry.created_at)
        self.assertIsNotNone(entry.updated_at)


class TestPasswordManager(unittest.TestCase):
    """Test PasswordManager class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.enc')
        self.temp_file.close()
        self.storage_path = self.temp_file.name
        self.master_password = "test_master_password"
    
    def tearDown(self):
        """Clean up test files"""
        if os.path.exists(self.storage_path):
            os.remove(self.storage_path)
    
    def test_init_new_manager(self):
        """Test initializing new password manager"""
        pm = PasswordManager(self.master_password, self.storage_path)
        self.assertEqual(len(pm.entries), 0)
        self.assertIsNotNone(pm.encryptor)
    
    def test_init_empty_password_raises_error(self):
        """Test that empty master password raises error"""
        with self.assertRaises(ValueError) as context:
            PasswordManager("", self.storage_path)
        self.assertIn("cannot be empty", str(context.exception))
    
    def test_add_entry(self):
        """Test adding an entry"""
        pm = PasswordManager(self.master_password, self.storage_path)
        entry = pm.add_entry("service", "user", "pass", "notes")
        self.assertEqual(entry.service, "service")
        self.assertEqual(len(pm.entries), 1)
    
    def test_add_duplicate_entry_raises_error(self):
        """Test that adding duplicate raises error"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass")
        with self.assertRaises(ValueError) as context:
            pm.add_entry("service", "user", "pass2")
        self.assertIn("already exists", str(context.exception))
    
    def test_get_entry(self):
        """Test getting an entry"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass")
        entry = pm.get_entry("service", "user")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.password, "pass")
    
    def test_get_nonexistent_entry(self):
        """Test getting nonexistent entry"""
        pm = PasswordManager(self.master_password, self.storage_path)
        entry = pm.get_entry("service", "user")
        self.assertIsNone(entry)
    
    def test_update_entry_password(self):
        """Test updating entry password"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass")
        entry = pm.update_entry("service", "user", new_password="newpass")
        self.assertEqual(entry.password, "newpass")
    
    def test_update_entry_notes(self):
        """Test updating entry notes"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass", "old notes")
        entry = pm.update_entry("service", "user", new_notes="new notes")
        self.assertEqual(entry.notes, "new notes")
    
    def test_update_entry_both(self):
        """Test updating both password and notes"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass", "old notes")
        entry = pm.update_entry("service", "user", 
                               new_password="newpass", 
                               new_notes="new notes")
        self.assertEqual(entry.password, "newpass")
        self.assertEqual(entry.notes, "new notes")
    
    def test_update_nonexistent_entry_raises_error(self):
        """Test updating nonexistent entry raises error"""
        pm = PasswordManager(self.master_password, self.storage_path)
        with self.assertRaises(ValueError) as context:
            pm.update_entry("service", "user", new_password="newpass")
        self.assertIn("not found", str(context.exception))
    
    def test_delete_entry(self):
        """Test deleting an entry"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass")
        result = pm.delete_entry("service", "user")
        self.assertTrue(result)
        self.assertEqual(len(pm.entries), 0)
    
    def test_delete_nonexistent_entry(self):
        """Test deleting nonexistent entry"""
        pm = PasswordManager(self.master_password, self.storage_path)
        result = pm.delete_entry("service", "user")
        self.assertFalse(result)
    
    def test_list_entries(self):
        """Test listing entries"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service1", "user1", "pass1")
        pm.add_entry("service2", "user2", "pass2")
        entries = pm.list_entries()
        self.assertEqual(len(entries), 2)
    
    def test_list_entries_with_filter(self):
        """Test listing entries with filter"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("gmail.com", "user1", "pass1")
        pm.add_entry("yahoo.com", "user2", "pass2")
        entries = pm.list_entries(service_filter="gmail")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].service, "gmail.com")
    
    def test_list_entries_sorted(self):
        """Test that entries are sorted by service"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("zservice", "user1", "pass1")
        pm.add_entry("aservice", "user2", "pass2")
        entries = pm.list_entries()
        self.assertEqual(entries[0].service, "aservice")
        self.assertEqual(entries[1].service, "zservice")
    
    def test_save_and_load(self):
        """Test saving and loading"""
        pm1 = PasswordManager(self.master_password, self.storage_path)
        pm1.add_entry("service", "user", "pass", "notes")
        pm1.save()
        
        pm2 = PasswordManager(self.master_password, self.storage_path)
        entry = pm2.get_entry("service", "user")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.password, "pass")
    
    def test_load_with_wrong_password_raises_error(self):
        """Test loading with wrong password raises error"""
        pm1 = PasswordManager(self.master_password, self.storage_path)
        pm1.add_entry("service", "user", "pass")
        pm1.save()
        
        with self.assertRaises(ValueError) as context:
            PasswordManager("wrong_password", self.storage_path)
        self.assertIn("Invalid master password", str(context.exception))
    
    def test_change_master_password(self):
        """Test changing master password"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass")
        result = pm.change_master_password(self.master_password, "new_password")
        self.assertTrue(result)
    
    def test_change_master_password_wrong_old_raises_error(self):
        """Test changing password with wrong old password"""
        pm = PasswordManager(self.master_password, self.storage_path)
        with self.assertRaises(ValueError) as context:
            pm.change_master_password("wrong", "new_password")
        self.assertIn("Invalid old password", str(context.exception))
    
    def test_change_master_password_empty_new_raises_error(self):
        """Test changing to empty password raises error"""
        pm = PasswordManager(self.master_password, self.storage_path)
        with self.assertRaises(ValueError) as context:
            pm.change_master_password(self.master_password, "")
        self.assertIn("cannot be empty", str(context.exception))
    
    def test_export_to_json_with_passwords(self):
        """Test exporting to JSON with passwords"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass", "notes")
        
        export_path = self.storage_path + ".json"
        try:
            result = pm.export_to_json(export_path, include_passwords=True)
            self.assertTrue(result)
            
            with open(export_path, 'r') as f:
                data = json.load(f)
            
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["password"], "pass")
        finally:
            if os.path.exists(export_path):
                os.remove(export_path)
    
    def test_export_to_json_without_passwords(self):
        """Test exporting to JSON without passwords"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass", "notes")
        
        export_path = self.storage_path + ".json"
        try:
            result = pm.export_to_json(export_path, include_passwords=False)
            self.assertTrue(result)
            
            with open(export_path, 'r') as f:
                data = json.load(f)
            
            self.assertEqual(data[0]["password"], "********")
        finally:
            if os.path.exists(export_path):
                os.remove(export_path)
    
    def test_export_to_json_failure(self):
        """Test export failure"""
        pm = PasswordManager(self.master_password, self.storage_path)
        result = pm.export_to_json("/invalid/path/file.json")
        self.assertFalse(result)
    
    def test_search_entries_by_service(self):
        """Test searching by service"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("gmail.com", "user1", "pass1")
        pm.add_entry("yahoo.com", "user2", "pass2")
        results = pm.search_entries("gmail")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].service, "gmail.com")
    
    def test_search_entries_by_username(self):
        """Test searching by username"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service1", "alice", "pass1")
        pm.add_entry("service2", "bob", "pass2")
        results = pm.search_entries("alice")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].username, "alice")
    
    def test_search_entries_by_notes(self):
        """Test searching by notes"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service1", "user1", "pass1", "important account")
        pm.add_entry("service2", "user2", "pass2", "test account")
        results = pm.search_entries("important")
        self.assertEqual(len(results), 1)
    
    def test_search_entries_empty_query(self):
        """Test searching with empty query"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass")
        results = pm.search_entries("")
        self.assertEqual(len(results), 0)
    
    def test_search_entries_sorted(self):
        """Test that search results are sorted"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("zservice", "test", "pass1")
        pm.add_entry("aservice", "test", "pass2")
        results = pm.search_entries("test")
        self.assertEqual(results[0].service, "aservice")
    
    def test_save_without_encryptor(self):
        """Test save without encryptor"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.encryptor = None
        result = pm.save()
        self.assertFalse(result)
    
    def test_save_with_exception(self):
        """Test save with exception"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass")
        
        # Force an error by making storage_path invalid
        pm.storage_path = "/invalid/path/file.enc"
        result = pm.save()
        self.assertFalse(result)
    
    def test_load_file_not_found(self):
        """Test load with missing file"""
        if os.path.exists(self.storage_path):
            os.remove(self.storage_path)
        
        with open(self.storage_path, 'w') as f:
            f.write("dummy")
        os.remove(self.storage_path)
        
        with self.assertRaises(ValueError) as context:
            PasswordManager(self.master_password, self.storage_path)
        self.assertIn("not found", str(context.exception))
    
    def test_load_corrupted_json(self):
        """Test load with corrupted JSON"""
        pm = PasswordManager(self.master_password, self.storage_path)
        pm.add_entry("service", "user", "pass")
        pm.save()
        
        # Corrupt the file
        with open(self.storage_path, 'w') as f:
            encrypted_data = pm.encryptor.encrypt("invalid json data")
            f.write(encrypted_data)
        
        with self.assertRaises(ValueError) as context:
            PasswordManager(self.master_password, self.storage_path)
        self.assertIn("Corrupted", str(context.exception))
    
    def test_load_invalid_encrypted_data(self):
        """Test load with invalid encrypted data"""
        with open(self.storage_path, 'w') as f:
            f.write("completely_invalid_data")
        
        with self.assertRaises(ValueError) as context:
            PasswordManager(self.master_password, self.storage_path)
        self.assertIn("Invalid master password or corrupted", str(context.exception))


class TestMainFunction(unittest.TestCase):
    """Test main function"""
    
    def test_main_execution(self):
        """Test main function execution"""
        with patch('builtins.print') as mock_print:
            main()
            mock_print.assert_called()
    
    def test_main_with_exception(self):
        """Test main function with exception"""
        with patch('main.PasswordManager') as mock_pm:
            mock_pm.side_effect = Exception("Test error")
            with patch('builtins.print') as mock_print:
                main()
                # Check that error was printed
                calls = [str(call) for call in mock_print.call_args_list]
                self.assertTrue(any("Error" in str(call) for call in calls))


if __name__ == '__main__':
    # Run tests with coverage
    unittest.main(verbosity=2)
