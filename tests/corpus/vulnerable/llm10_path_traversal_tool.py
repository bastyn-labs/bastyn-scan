"""OpsBot's document-retrieval MCP tool.

Reads runbook documents from a fixed directory, keyed by a caller-supplied
filename.
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("opsbot")

RUNBOOK_DIR = "/srv/opsbot/runbooks"


@mcp.tool()
def read_runbook(filename: str) -> str:
    """BAS-LLM10-012: filename is joined onto the runbook directory and
    opened with no realpath/containment check -- '../../etc/passwd'
    escapes RUNBOOK_DIR entirely."""
    with open(os.path.join(RUNBOOK_DIR, filename)) as handle:
        return handle.read()


@mcp.tool()
def read_runbook_prefix_checked(filename: str) -> str:
    """BAS-LLM10-012: a check exists, but it is a string-prefix test on
    the unresolved path -- 'runbooks_evil/../../etc/passwd' can still
    satisfy a naive prefix test depending on how it is built, and even
    when it doesn't, the open() call itself still has no realpath
    wrapper around it, which is what this rule actually inspects."""
    if not f"{RUNBOOK_DIR}/{filename}".startswith(RUNBOOK_DIR):
        raise PermissionError("outside runbook directory")
    with open(f"{RUNBOOK_DIR}/{filename}") as handle:
        return handle.read()


@mcp.tool()
def read_bundled_asset(asset_root: str, filename: str) -> str:
    """LLM10 (BAS-LLM10-012): asset_root is a function parameter, not a
    module-level __file__-derived constant -- exclude_if: constant_path
    does not (and by design cannot, without interprocedural call-site
    analysis) prove it safe, so this must still fire."""
    with open(os.path.join(asset_root, filename)) as handle:
        return handle.read()


from pathlib import Path

HERE = Path(__file__).parent


@mcp.tool()
def read_user_file(name: str) -> str:
    """BAS-LLM10-012: HERE is a module-level, __file__-derived constant_path
    built via pathlib, but name is a function parameter interpolated
    into the same f-string. exclude_if: constant_path ANDs every
    interpolation with the surrounding literal text, so mixing a parameter
    into an otherwise-constant f-string must still fire."""
    return open(f"{HERE}/uploads/{name}").read()


import argparse
from flask import request


def export() -> str:
    """BAS-LLM10-012: args.root traces to the operator's own command line
    (argparse's parse_args()) -- exclude_if: cli_argument
    would suppress that half on its own -- but it is joined with
    request.args["f"], flask's own HTTP query-parameter dict, a second
    non-literal segment cli_argument knows nothing about. Both
    exclude_if: constant_path and exclude_if: cli_argument AND their
    predicate across every argument of os.path.join, so mixing one
    CLI-sourced segment with one HTTP-sourced segment must still fire."""
    args = argparse.ArgumentParser().parse_args()
    return open(os.path.join(args.root, request.args["f"])).read()
