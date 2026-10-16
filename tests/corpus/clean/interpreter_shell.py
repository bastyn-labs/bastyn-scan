"""Shell commands built only from the running interpreter's path and fixed
text. BAS-LLM10-009's exclude_if: closed_value treats sys.executable as a value
no request or model supplies, so a command made of it and literals is not
reported. See tests/corpus/vulnerable/llm10_shell_interpreter_with_parameter.py
for the sibling that adds a caller-supplied package name.
"""

import os
import subprocess
import sys

BUILD_COMMAND = "make all"


def install_requests() -> None:
    os.system(f"{sys.executable} -m pip install requests -q")


def run_build() -> None:
    subprocess.run(BUILD_COMMAND, shell=True, check=False)


def show_version() -> None:
    subprocess.run(f"{sys.executable} --version", shell=True, check=False)
