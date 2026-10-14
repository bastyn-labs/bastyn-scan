from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes", host="0.0.0.0", port=8000)


@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
