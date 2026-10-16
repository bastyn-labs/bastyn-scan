"""A joined path is a defect when a segment is client-chosen whoever calls
the function (HTTP request data), or when a function parameter belongs to an
entry point or to a helper an entry point calls in this file."""

import os

from flask import Flask, request
from mcp.server.fastmcp import FastMCP

app = Flask(__name__)
mcp = FastMCP("reports")

REPORT_DIR = "/var/reports"


def load_report(name: str) -> str:
    """Defect: reached from the read_report() tool below, which hands it a
    caller-chosen name."""
    with open(os.path.join(REPORT_DIR, name)) as handle:
        return handle.read()


@mcp.tool()
def read_report(name: str) -> str:
    return load_report(name)


def serve_report() -> str:
    """Defect: the path carries HTTP request data, so it is caller-chosen
    even though this function is not a registered handler."""
    with open(os.path.join(REPORT_DIR, request.args["name"])) as handle:
        return handle.read()
