"""A list command whose first element is a literal runs a fixed program through the shell."""

import subprocess
import sys


def open_in_viewer(path: str):
    if sys.platform == "win32":
        subprocess.run(["start", str(path)], shell=True, check=False)
    else:
        subprocess.Popen(['xdg-open', path], shell=True)
