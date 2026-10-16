"""BAS-LLM10-012's flow.unreached_parameter_downgrade: a path joined from a
function's own parameter is reported as an observation, not a defect, when
the function is not a recognized agent- or web-framework entry point
(@mcp.tool()/@app.route()/a do_GET-style handler) and no such entry point in
this file calls it. See bastyn.yml's comment on BAS-LLM10-012 and
crate::flow::graph::FlowGraph::is_unreached_parameter_input.
"""

import os

RESULTS = "/var/reports/results"


def load_result(name: str) -> str:
    """Observation: name is a parameter of a helper that nothing in this
    file reaches from an entry point."""
    with open(os.path.join(RESULTS, name)) as handle:
        return handle.read()


def load_all_results() -> tuple[str, str]:
    return load_result("summary.json"), load_result("detail.json")
