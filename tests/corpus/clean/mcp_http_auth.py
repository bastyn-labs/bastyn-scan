from mcp.server.fastmcp import FastMCP

provider = object()

mcp = FastMCP("notes", host="0.0.0.0", auth=provider)


@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
