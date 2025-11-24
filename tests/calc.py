# tests/test_vault.py

import unittest
from src.vault import Vault

class TestVault(unittest.TestCase):
    def setUp(self):
        self.vault = Vault()

    def test_add_and_get(self):
        result = self.vault.add("gmail", "user1", "pass1")
        self.assertTrue(result)
        self.assertEqual(self.vault.get("gmail", "user1"), "pass1")

    def test_add_duplicate(self):
        self.vault.add("gmail", "user1", "pass1")
        result = self.vault.add("gmail", "user1", "pass2")
        self.assertFalse(result)
        self.assertEqual(self.vault.get("gmail", "user1"), "pass1")

    def test_delete(self):
        self.vault.add("gmail", "user1", "pass1")
        result = self.vault.delete("gmail", "user1")
        self.assertTrue(result)
        self.assertIsNone(self.vault.get("gmail", "user1"))

    def test_delete_nonexistent(self):
        result = self.vault.delete("gmail", "user2")
        self.assertFalse(result)

    def test_list_entries(self):
        self.vault.add("gmail", "user1", "pass1")
        self.vault.add("yahoo", "user2", "pass2")
        entries = self.vault.list_entries()
        self.assertIn(("gmail", "user1"), entries)
        self.assertIn(("yahoo", "user2"), entries)

if __name__ == "__main__":
    unittest.main()
