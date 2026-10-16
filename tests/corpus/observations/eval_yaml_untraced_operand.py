"""eval/exec and yaml.load whose operand does not trace to a parameter or other external input."""

import ast

import yaml

SCAFFOLDS = {"first": "x = 1", "second": "y = 2"}
TEMPLATE = "z = 3"


def render(template):
    return template + "\n"


def run_every_scaffold():
    for name, code in sorted(SCAFFOLDS.items()):
        exec(compile(code, name, "exec"), {})


def run_rendered_template():
    source = render(TEMPLATE)
    exec(source, {})


def evaluate_parsed(text):
    tree = ast.parse(text, mode="eval")
    return eval(compile(tree, "<expr>", "eval"), {"__builtins__": {}})


def parse_helper_result():
    raw = render(TEMPLATE)
    return yaml.load(raw)
