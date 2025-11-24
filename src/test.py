# test_password_manager.py
import os
import tempfile
import unittest
from main import PasswordManager


class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        # create a temporary file path (do not create the file yet)
        fd, self.path = tempfile.mkstemp(prefix="vault_test_", suffix=".json")
        os.close(fd)
        os.remove(self.path)  # manager will initialize it
        self.master = "strong-master-pass"
        self.pm = PasswordManager(self.path, master_password=self.master)

    def tearDown(self):
        try:
            os.remove(self.path)
        except OSError:
            pass

    def test_add_get_delete(self):
        ok = self.pm.add("gmail", "alice", "alicepass")
        self.assertTrue(ok)
        # get
        pwd = self.pm.get("gmail", "alice")
        self.assertEqual(pwd, "alicepass")
        # delete
        deleted = self.pm.delete("gmail", "alice")
        self.assertTrue(deleted)
        self.assertIsNone(self.pm.get("gmail", "alice"))

    def test_add_duplicate(self):
        self.assertTrue(self.pm.add("service", "bob", "p1"))
        self.assertFalse(self.pm.add("service", "bob", "p2"))
        # original remains
        self.assertEqual(self.pm.get("service", "bob"), "p1")

    def test_list_entries(self):
        self.pm.add("s1", "u1", "p1")
        self.pm.add("s2", "u2", "p2")
        entries = set(self.pm.list_entries())
        self.assertEqual(entries, {("s1", "u1"), ("s2", "u2")})

    def test_persistence_and_reload(self):
        # add entries and ensure they persist to disk
        self.pm.add("site", "user", "secret")
        # create a new manager instance pointing at same path with same master password
        pm2 = PasswordManager(self.path, master_password=self.master)
        self.assertEqual(pm2.get("site", "user"), "secret")
        # ensure list_entries works after reload
        self.assertIn(("site", "user"), pm2.list_entries())

    def test_wrong_master_password(self):
        self.pm.add("host", "root", "rootpass")
        # open with a wrong master password
        pm_wrong = PasswordManager(self.path, master_password="incorrect")
        # The stored ciphertext will fail to decrypt correctly -> get returns None
        self.assertIsNone(pm_wrong.get("host", "root"))

    def test_invalid_init(self):
        with self.assertRaises(ValueError):
            PasswordManager("dummy", master_password="")  # empty master not allowed

    def test_malformed_storage(self):
        # write bad json to file
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"invalid": true}')
        with self.assertRaises(ValueError):
            PasswordManager(self.path, master_password=self.master)


if __name__ == "__main__":
    unittest.main()

