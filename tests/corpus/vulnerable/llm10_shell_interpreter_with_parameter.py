"""A shell command that starts from the interpreter's path but also splices in
a caller-supplied package name. The interpreter segment is fixed; the package
segment is not, so the command is still reported.
"""

import os
import sys


def install_package(package):
    os.system(f"{sys.executable} -m pip install {package}")
