import unittest

class TestExample(unittest.TestCase):

    def test_sample(self):
        self.assertEqual(1 + 1, 2)

    def test_true(self):
        self.assertTrue(True)

if __name__ == "__main__":
    unittest.main()
