import re


def evaluate_checked(expression):
    """A full match on digits, parentheses and operators, rejected otherwise."""
    if not re.fullmatch(r"[0-9+\-*/%(). ]+", expression):
        raise ValueError("unsupported characters")
    return eval(expression)


def evaluate_filtered(expression):
    """Everything outside the same character set is removed first."""
    cleaned = re.sub(r"[^0-9+\-*/%(). ]", "", expression).strip()
    if not cleaned:
        return None
    return eval(cleaned)


def evaluate_digits_only(expression):
    if not expression.isdigit():
        raise ValueError("digits only")
    return eval(expression)
