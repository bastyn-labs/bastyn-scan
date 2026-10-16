"""A list command through a shell is reported when its first element is not a literal."""

import subprocess


def launch(program: str, target: str):
    subprocess.run([program, target], shell=True, check=False)
