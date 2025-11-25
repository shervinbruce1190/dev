# test_main.py
import unittest
import os
import json
import tempfile
import base64
from unittest.mock import patch

from main import (
    PasswordStrengthChecker,
    PasswordGenerator,
    Encryptor,
    PasswordEntry,
    PasswordManager,
    main
)


class TestPasswordStrengthChecker(unittest.TestCase):

    def test_empty_password(self):
        r = PasswordStrengthChecker.check_strength("")
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["strength"], "empty")
        self.assertIn("Password cannot be empty", r["feedback"])

    def test_weak_password(self):
        r = PasswordStrengthChecker.check_strength("abc")
        self.assertEqual(r["strength"], "weak")
        self.assertLessEqual(r["score"], 2)

    def test_medium_password(self):
        r = PasswordStrengthChecker.check_strength("Abcd1234")
        self.assertIn(r["strength"], ("weak", "medium"))

    def test_strong_password(self):
        r = PasswordStrengthChecker.check_strength("Abcd1234!@#$")
        self.assertEqual(r["strength"], "strong")
        self.assertGreater(r["score"], 4)

    def test_feedback_messages(self):
        # Missing uppercase
        r = PasswordStrengthChecker.check_strength("abcd1234!@#$")
        self.assertIn("Add uppercase letters", r["feedback"])


class TestPasswordGenerator(unittest.TestCase):

    def test_default_length(self):
        pw = PasswordGenerator.generate()
        self.assertEqual(len(pw), 16)

    def test_custom_length(self):
        pw = PasswordGenerator.generate(length=20)
        self.assertEqual(len(pw), 20)

    def test_min_length_allowed(self):
        pw = PasswordGenerator.generate(length=4)
        self.assertEqual(len(pw), 4)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            PasswordGenerator.generate(length=3)

    def test_must_select_type(self):
        with self.assertRaises(ValueError):
            PasswordGenerator.generate(
                use_symbols=False, use_numbers=False, use_uppercase=False, use_lowercase=False
            )

    def test_only_lowercase(self):
        pw = PasswordGenerator.generate(length=12, use_symbols=False, use_numbers=False, use_uppercase=False, use_lowercase=True)
        self.assertTrue(all(c.islower() for c in pw))

    def test_only_numbers(self):
        pw = PasswordGenerator.generate(length=8, use_symbols=False, use_numbers=True, use_uppercase=False, use_lowercase=False)
        self.assertTrue(all(c.isdigit() for c in pw))


class TestEncryptor(unittest.TestCase):

    def test_init_and_salt(self):
        enc = Encryptor("masterpass")
        self.assertIsInstance(enc.get_salt(), bytes)
        self.assertEqual(len(enc.get_salt()), 16)
        self.assertTrue(hasattr(enc, "_key"))

    def test_init_empty_password_raises(self):
        with self.assertRaises(ValueError):
            Encryptor("")

    def test_init_with_custom_salt(self):
        salt = os.urandom(16)
        enc = Encryptor("m", salt=salt)
        self.assertEqual(enc.get_salt(), salt)

    def test_encrypt_decrypt_roundtrip(self):
        enc = Encryptor("masterpass")
        original = "somedata"
        ciphertext = enc.encrypt(original)
        self.assertIsInstance(ciphertext, str)
        plaintext = enc.decrypt(ciphertext)
        self.assertEqual(plaintext, original)

    def test_encrypt_none_raises(self):
        enc = Encryptor("masterpass")
        with self.assertRaises(ValueError):
            enc.encrypt(None)

    def test_encrypt_empty_string_allowed_but_encrypt_raises_in_main(self):
        # In this implementation, encrypt("") returns a token; main.Encryptor.encrypt raises only on None.
        enc = Encryptor("masterpass")
        token = enc.encrypt("")  # should produce valid encrypted string
        self.assertIsInstance(token, str)
        self.assertNotEqual(token, "")

    def test_decrypt_empty_raises(self):
        enc = Encryptor("masterpass")
        with self.assertRaises(ValueError):
            enc.decrypt("")

    def test_decrypt_invalid_raises(self):
        enc = Encryptor("masterpass")
        with self.assertRaises(ValueError):
            enc.decrypt("invalid_data")

    def test_different_passwords_produce_different_ciphertexts(self):
        data = "hello"
        e1 = Encryptor("p1")
        e2 = Encryptor("p2")
        c1 = e1.encrypt(data)
        c2 = e2.encrypt(data)
        self.assertNotEqual(c1, c2)


class TestPasswordEntry(unittest.TestCase):

    def test_create_and_to_dict(self):
        e = PasswordEntry("svc", "user", "pwd", "notes")
        d = e.to_dict()
        self.assertEqual(d["service"], "svc")
        self.assertEqual(d["username"], "user")
        self.assertEqual(d["password"], "pwd")
        self.assertEqual(d["notes"], "notes")
        self.assertIn("created_at", d)
        self.assertIn("updated_at", d)

    def test_from_dict_and_timestamps(self):
        data = {"service": "svc", "username": "u", "password": "p"}
        e = PasswordEntry.from_dict(data)
        self.assertEqual(e.service, "svc")
        self.assertEqual(e.username, "u")
        self.assertEqual(e.password, "p")
        self.assertIsNotNone(e.created_at)
        self.assertIsNotNone(e.updated_at)

    def test_constructor_validations(self):
        with self.assertRaises(ValueError):
            PasswordEntry("", "u", "p")
        with self.assertRaises(ValueError):
            PasswordEntry("s", "", "p")
        # password may be empty string (not None) per implementation
        e = PasswordEntry("s", "u", "")
        self.assertEqual(e.password, "")


class TestPasswordManagerPersistenceAndOps(unittest.TestCase):

    def setUp(self):
        # create a path that does not exist so PasswordManager creates a new store
        fd, self.path = tempfile.mkstemp(suffix=".enc")
        os.close(fd)
        # remove the file so constructor will initialize new storage
        try:
            os.remove(self.path)
        except OSError:
            pass
        self.master = "test_master"

    def tearDown(self):
        try:
            if os.path.exists(self.path):
                os.remove(self.path)
        except Exception:
            pass
        # also remove any .json exports
        try:
            if os.path.exists(self.path + ".json"):
                os.remove(self.path + ".json")
        except Exception:
            pass

    def test_init_new_manager(self):
        pm = PasswordManager(self.master, self.path)
        self.assertEqual(len(pm.entries), 0)
        self.assertIsNotNone(pm.encryptor)

    def test_init_empty_master_raises(self):
        with self.assertRaises(ValueError):
            PasswordManager("", self.path)

    def test_add_and_get_entry(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p", "n")
        e = pm.get_entry("svc", "u")
        self.assertIsNotNone(e)
        self.assertEqual(e.password, "p")

    def test_add_duplicate_raises(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p")
        with self.assertRaises(ValueError):
            pm.add_entry("svc", "u", "p2")

    def test_update_entry(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p", "old")
        pm.update_entry("svc", "u", new_password="np", new_notes="nn")
        e = pm.get_entry("svc", "u")
        self.assertEqual(e.password, "np")
        self.assertEqual(e.notes, "nn")

    def test_update_nonexistent_raises(self):
        pm = PasswordManager(self.master, self.path)
        with self.assertRaises(ValueError):
            pm.update_entry("svc", "u", new_password="x")

    def test_delete_entry(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p")
        self.assertTrue(pm.delete_entry("svc", "u"))
        self.assertIsNone(pm.get_entry("svc", "u"))

    def test_delete_nonexistent(self):
        pm = PasswordManager(self.master, self.path)
        self.assertFalse(pm.delete_entry("no", "one"))

    def test_list_and_filter_and_sort(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("zsvc", "a", "p")
        pm.add_entry("asvc", "b", "p")
        all_entries = pm.list_entries()
        self.assertEqual(all_entries[0].service, "asvc")
        filtered = pm.list_entries(service_filter="z")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].service, "zsvc")

    def test_save_and_load_roundtrip(self):
        pm1 = PasswordManager(self.master, self.path)
        pm1.add_entry("svc", "u", "p", "note")
        saved = pm1.save()
        self.assertTrue(saved)

        # load with same password
        pm2 = PasswordManager(self.master, self.path)
        e = pm2.get_entry("svc", "u")
        self.assertIsNotNone(e)
        self.assertEqual(e.password, "p")

    def test_load_with_wrong_master_raises(self):
        pm1 = PasswordManager(self.master, self.path)
        pm1.add_entry("svc", "u", "p")
        pm1.save()

        with self.assertRaises(ValueError) as cm:
            PasswordManager("wrong", self.path)
        self.assertIn("Invalid master password", str(cm.exception))

    def test_change_master_password(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p")
        result = pm.change_master_password(self.master, "newmaster")
        self.assertTrue(result)
        # ensure new manager can load with new password
        pm2 = PasswordManager("newmaster", self.path)
        self.assertIsNotNone(pm2.get_entry("svc", "u"))

    def test_change_master_password_wrong_old_raises(self):
        pm = PasswordManager(self.master, self.path)
        with self.assertRaises(ValueError):
            pm.change_master_password("bad", "new")

    def test_change_master_password_empty_new_raises(self):
        pm = PasswordManager(self.master, self.path)
        with self.assertRaises(ValueError):
            pm.change_master_password(self.master, "")

    def test_export_to_json_include_and_exclude(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p")
        out = self.path + ".json"
        try:
            ok = pm.export_to_json(out, include_passwords=True)
            self.assertTrue(ok)
            with open(out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data[0]["password"], "p")

            ok2 = pm.export_to_json(out, include_passwords=False)
            self.assertTrue(ok2)
            with open(out, "r", encoding="utf-8") as fh:
                data2 = json.load(fh)
            self.assertEqual(data2[0]["password"], "********")
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_export_failure(self):
        pm = PasswordManager(self.master, self.path)
        # invalid path should return False
        self.assertFalse(pm.export_to_json("/this/path/does/not/exist.json"))

    def test_search_entries(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("gmail.com", "alice", "p")
        pm.add_entry("yahoo.com", "bob", "p2", "important")
        r1 = pm.search_entries("gmail")
        self.assertEqual(len(r1), 1)
        r2 = pm.search_entries("alice")
        self.assertEqual(len(r2), 1)
        r3 = pm.search_entries("important")
        self.assertEqual(len(r3), 1)
        self.assertEqual(pm.search_entries(""), [])

    def test_save_without_encryptor_returns_false(self):
        pm = PasswordManager(self.master, self.path)
        pm.encryptor = None
        self.assertFalse(pm.save())

    def test_save_with_invalid_path_returns_false(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p")
        pm.storage_path = "/invalid/path/abc.enc"
        self.assertFalse(pm.save())

    def test_load_missing_file_raises(self):
        # ensure file missing
        if os.path.exists(self.path):
            os.remove(self.path)
        # create then remove to simulate missing - constructor will raise FileNotFoundError -> ValueError
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("dummy")
        os.remove(self.path)
        with self.assertRaises(ValueError):
            PasswordManager(self.master, self.path)

    def test_load_corrupted_json_raises(self):
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p")
        pm.save()

        # Corrupt file by writing non-JSON
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("not a json")
        with self.assertRaises(ValueError) as cm:
            PasswordManager(self.master, self.path)
        self.assertIn("Corrupted data file", str(cm.exception))

    def test_load_invalid_encrypted_payload_raises(self):
        # write valid JSON structure but entries_encrypted is invalid -> should raise "Failed to decrypt entries..."
        pm = PasswordManager(self.master, self.path)
        pm.add_entry("svc", "u", "p")
        pm.save()

        # load raw file, replace entries_encrypted with an invalid base64 string
        with open(self.path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["entries_encrypted"] = "not_base64_ciphertext"
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)

        with self.assertRaises(ValueError) as cm:
            PasswordManager(self.master, self.path)
        self.assertIn("Failed to decrypt entries", str(cm.exception))


class TestMainFunction(unittest.TestCase):

    def test_main_runs_and_prints(self):
        # patch print to avoid console spam, ensure it is called
        with patch("builtins.print") as mock_print:
            main()
            self.assertTrue(mock_print.called)

    def test_main_handles_exception_and_prints_error(self):
        # force PasswordManager constructor to raise
        with patch("main.PasswordManager", side_effect=Exception("boom")):
            with patch("builtins.print") as mock_print:
                main()
                # one of the printed lines should include "Error"
                called = False
                for call in mock_print.call_args_list:
                    if any("Error" in str(arg) for arg in call[0]):
                        called = True
                self.assertTrue(called)


if __name__ == "__main__":
    unittest.main(verbosity=2)
