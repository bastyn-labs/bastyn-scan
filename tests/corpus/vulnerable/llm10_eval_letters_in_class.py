import re


def evaluate_with_names(expression):
    """The class admits letters and underscores, so names, attribute access
    and calls can pass the full match."""
    if not re.fullmatch(r"[0-9a-z_+\-*/(). ]+", expression):
        raise ValueError("unsupported characters")
    return eval(expression)


def evaluate_unanchored(expression):
    """`re.search` without anchors only finds one allowed character; the rest
    of the value is unchecked."""
    if not re.search(r"[0-9+\-*/(). ]+", expression):
        raise ValueError("no arithmetic found")
    return eval(expression)


def evaluate_after_reassignment(expression):
    """The check no longer describes the value that reaches eval."""
    if not re.fullmatch(r"[0-9+\-*/(). ]+", expression):
        raise ValueError("unsupported characters")
    expression = expression + ".__class__"
    return eval(expression)
