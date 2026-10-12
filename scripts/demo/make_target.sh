#!/bin/sh
# Assemble the demo folder from three public, intentionally vulnerable projects.
# Usage: make_target.sh OUT_DIR MCP_SERVER_DIR AGENT_SCENARIOS_DIR SERVICE_DIR
set -eu
out="$1/advanced-hil-credit-pre-approval"
rm -rf "$out"; mkdir -p "$out"
copy() { mkdir -p "$out/$2"; (cd "$1" && tar --exclude=.git -cf - .) | (cd "$out/$2" && tar -xf -); }
copy "$2" mcp-server
copy "$3" agent-scenarios
copy "$4" scoring-service
