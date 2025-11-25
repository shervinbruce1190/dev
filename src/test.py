# test_matrix.py

import unittest
from main import Matrix

class TestMatrix(unittest.TestCase):

    def test_init_valid(self):
        m = Matrix([[1, 2], [3, 4]])
        self.assertEqual(m.data, [[1, 2], [3, 4]])

    def test_init_invalid(self):
        with self.assertRaises(ValueError):
            Matrix([])
        with self.assertRaises(ValueError):
            Matrix([[]])
        with self.assertRaises(ValueError):
            Matrix([[1, 2], [3]])

    def test_add_valid(self):
        a = Matrix([[1, 2], [3, 4]])
        b = Matrix([[5, 6], [7, 8]])
        result = a.add(b)
        self.assertEqual(result, Matrix([[6, 8], [10, 12]]))

    def test_add_invalid(self):
        a = Matrix([[1, 2]])
        with self.assertRaises(TypeError):
            a.add("not matrix")
        b = Matrix([[1], [2]])
        with self.assertRaises(ValueError):
            a.add(b)

    def test_subtract_valid(self):
        a = Matrix([[5, 6], [7, 8]])
        b = Matrix([[1, 2], [3, 4]])
        result = a.subtract(b)
        self.assertEqual(result, Matrix([[4, 4], [4, 4]]))

    def test_subtract_invalid(self):
        a = Matrix([[1, 2]])
        with self.assertRaises(TypeError):
            a.subtract("not matrix")
        b = Matrix([[1], [2]])
        with self.assertRaises(ValueError):
            a.subtract(b)

    def test_multiply_valid(self):
        a = Matrix([[1, 2], [3, 4]])
        b = Matrix([[2, 0], [1, 2]])
        result = a.multiply(b)
        self.assertEqual(result, Matrix([[4, 4], [10, 8]]))

    def test_multiply_invalid(self):
        a = Matrix([[1, 2]])
        with self.assertRaises(TypeError):
            a.multiply(123)
        b = Matrix([[1, 2, 3]])
        with self.assertRaises(ValueError):
            a.multiply(b)

    def test_shape(self):
        m = Matrix([[1, 2], [3, 4]])
        self.assertEqual(m.shape(), (2, 2))

    def test_eq(self):
        self.assertTrue(Matrix([[1]]) == Matrix([[1]]))
        self.assertFalse(Matrix([[1]]) == Matrix([[2]]))
        self.assertFalse(Matrix([[1]]) == "not matrix")

if __name__ == "__main__":
    unittest.main()
