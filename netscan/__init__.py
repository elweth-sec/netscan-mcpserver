from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "netscan",
    instructions=(
        "Network scanning and reconnaissance tools wrapping the netscan CLI. "
        "Only scan networks and systems you are authorized to test."
    ),
)

__all__ = ["mcp"]
