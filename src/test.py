import unittest
from main import Vault

class TestVault(unittest.TestCase):

    def setUp(self):
        self.vault = Vault()

    # ---------- ADD TESTS ----------
    def test_add_success(self):
        result = self.vault.add("gmail", "user1", "pass1")
        self.assertTrue(result)

    def test_add_duplicate(self):
        self.vault.add("gmail", "user1", "pass1")
        result = self.vault.add("gmail", "user1", "pass2")
        self.assertFalse(result)

    def test_add_invalid_inputs(self):
        self.assertFalse(self.vault.add("", "user1", "pass"))
        self.assertFalse(self.vault.add("gmail", "", "pass"))
        self.assertFalse(self.vault.add("gmail", "user1", ""))
        self.assertFalse(self.vault.add(123, "user1", "pass"))
        self.assertFalse(self.vault.add("gmail", None, "pass"))

    # ---------- GET TESTS ----------
    def test_get_success(self):
        self.vault.add("gmail", "user1", "pass1")
        self.assertEqual(self.vault.get("gmail", "user1"), "pass1")

    def test_get_not_found(self):
        self.assertIsNone(self.vault.get("gmail", "user1"))

    def test_get_invalid(self):
        self.assertIsNone(self.vault.get("", "user1"))
        self.assertIsNone(self.vault.get("gmail", ""))

    # ---------- DELETE TESTS ----------
    def test_delete_success(self):
        self.vault.add("gmail", "user1", "pass1")
        self.assertTrue(self.vault.delete("gmail", "user1"))

    def test_delete_not_found(self):
        self.assertFalse(self.vault.delete("gmail", "user1"))

    def test_delete_invalid(self):
        self.assertFalse(self.vault.delete("", "user1"))
        self.assertFalse(self.vault.delete("gmail", ""))

    # ---------- LIST TESTS ----------
    def test_list_entries(self):
        self.vault.add("gmail", "user1", "pass1")
        self.vault.add("facebook", "user2", "pass2")
        entries = self.vault.list_entries()
        self.assertIn(("gmail", "user1"), entries)
        self.assertIn(("facebook", "user2"), entries)

if __name__ == "__main__":
    unittest.main()
