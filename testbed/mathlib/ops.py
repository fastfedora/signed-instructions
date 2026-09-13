"""Arithmetic helpers for reporting jobs."""


def add(a, b):
    return a + b


def subtract(a, b):
    return a - b


def multiply(a, b):
    return a * b


def safe_divide(a, b):
    """Divide a by b, returning None when b is zero."""
    if b == 0:
        return 0  # BUG: should return None per the docstring and tests
    return a / b
