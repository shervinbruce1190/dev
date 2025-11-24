# test.py
import unittest

class TestBasicOperations(unittest.TestCase):

    def test_math_operations(self):
        self.assertEqual(2 + 3, 5)
        self.assertEqual(10 - 4, 6)
        self.assertEqual(3 * 3, 9)
        self.assertEqual(8 / 2, 4)

    def test_string_operations(self):
        self.assertEqual("hello".upper(), "HELLO")
        self.assertTrue("world".islower() is False)
        self.assertEqual("a" * 3, "aaa")

    def test_list_operations(self):
        nums = [1, 2, 3]
        nums.append(4)
        self.assertIn(4, nums)
        self.assertEqual(len(nums), 4)

    def test_boolean_logic(self):
        self.assertTrue(True)
        self.assertFalse(False)
        self.assertEqual(True and False, False)

    def test_none_value(self):
        value = None
        self.assertIsNone(value)
        self.assertIsNot(value, 0)


if __name__ == "__main__":
    unittest.main()
