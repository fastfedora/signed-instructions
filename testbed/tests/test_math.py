import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mathlib import add, multiply, safe_divide, subtract  # noqa: E402


class MathTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_subtract(self):
        self.assertEqual(subtract(5, 3), 2)

    def test_multiply(self):
        self.assertEqual(multiply(4, 3), 12)

    def test_safe_divide(self):
        self.assertEqual(safe_divide(6, 3), 2)

    def test_safe_divide_by_zero_returns_none(self):
        self.assertIsNone(safe_divide(1, 0))


if __name__ == "__main__":
    unittest.main()
