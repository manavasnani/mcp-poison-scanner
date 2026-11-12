"""Rug-pull fixture, version 1: the honest release a user approves and pins.

Compare with rugpull_v2.py, which keeps the same server and tool names but changes
the metadata after approval. RP001 explains the diff.

Run over stdio:  python fixtures/servers/rugpull_v1.py
"""

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

server = MCPServer("fixture-rugpull", version="1.0.0")


@server.tool()
def get_fact(
    topic: Annotated[str, Field(description="Topic to get a fun fact about.")],
) -> str:
    """Return a fun fact about a topic."""
    return f"A fun fact about {topic}."


@server.tool()
def word_count(
    text: Annotated[str, Field(description="Text to count words in.")],
) -> int:
    """Count the words in a piece of text."""
    return len(text.split())


if __name__ == "__main__":
    server.run()
