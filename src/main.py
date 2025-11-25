# main.py

class Matrix:
    """
    Simple matrix implementation without using external modules.
    Supports addition, subtraction, and multiplication.
    """

    def __init__(self, data):
        if not isinstance(data, list) or not data:
            raise ValueError("Matrix must be a non-empty list.")
        for row in data:
            if not isinstance(row, list) or not row:
                raise ValueError("Each row must be a non-empty list.")
        row_len = len(data[0])
        for row in data:
            if len(row) != row_len:
                raise ValueError("All rows must have equal length.")
        self.data = data

    def add(self, other):
        if not isinstance(other, Matrix):
            raise TypeError("Operand must be a Matrix.")
        if self.shape() != other.shape():
            raise ValueError("Matrix sizes must match for addition.")
        result = [
            [self.data[r][c] + other.data[r][c] for c in range(len(self.data[0]))]
            for r in range(len(self.data))
        ]
        return Matrix(result)

    def subtract(self, other):
        if not isinstance(other, Matrix):
            raise TypeError("Operand must be a Matrix.")
        if self.shape() != other.shape():
            raise ValueError("Matrix sizes must match for subtraction.")
        result = [
            [self.data[r][c] - other.data[r][c] for c in range(len(self.data[0]))]
            for r in range(len(self.data))
        ]
        return Matrix(result)

    def multiply(self, other):
        if not isinstance(other, Matrix):
            raise TypeError("Operand must be a Matrix.")
        if len(self.data[0]) != len(other.data):
            raise ValueError("Matrix A columns must match Matrix B rows.")
        result = []
        for r in range(len(self.data)):
            row = []
            for c in range(len(other.data[0])):
                value = 0
                for k in range(len(other.data)):
                    value += self.data[r][k] * other.data[k][c]
                row.append(value)
            result.append(row)
        return Matrix(result)

    def shape(self):
        return len(self.data), len(self.data[0])

    def __eq__(self, other):
        if not isinstance(other, Matrix):
            return False
        return self.data == other.data
