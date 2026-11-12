"""Clean fixture server: ordinary, honest metadata. No rule should fire on it.

Run over stdio:  python fixtures/servers/clean.py
"""

from typing import Annotated, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import Field

server = MCPServer(
    "fixture-clean",
    version="1.0.0",
    instructions="A small note-taking server. Notes are kept in memory and lost on restart.",
)

_NOTES: dict[str, str] = {}


@server.tool()
def add_note(
    title: Annotated[str, Field(description="Short title for the note.")],
    body: Annotated[str, Field(description="Text of the note.")],
) -> str:
    """Save a note under a title. Overwrites any note with the same title."""
    _NOTES[title] = body
    return f"saved {title}"


@server.tool()
def search_notes(
    query: Annotated[str, Field(description="Words to look for in note titles and bodies.")],
    limit: Annotated[int, Field(description="Maximum number of results.", ge=1, le=50)] = 10,
) -> list[str]:
    """Return titles of notes that contain the query, case-insensitive."""
    q = query.lower()
    return [t for t, b in _NOTES.items() if q in t.lower() or q in b.lower()][:limit]


@server.tool()
def format_note(
    title: Annotated[str, Field(description="Title of an existing note.")],
    style: Annotated[Literal["plain", "markdown", "html"], Field(description="Output format.")] = "plain",
) -> str:
    """Render a saved note in the chosen format."""
    body = _NOTES.get(title, "")
    if style == "markdown":
        return f"# {title}\n\n{body}"
    if style == "html":
        return f"<h1>{title}</h1><p>{body}</p>"
    return f"{title}\n{body}"


@server.prompt(description="Ask the model to summarise one note in three bullet points.")
def summarize_note(title: str) -> str:
    return f"Summarise the note titled {title!r} in three bullet points."


@server.resource("notes://index", description="List of all note titles, one per line.", mime_type="text/plain")
def notes_index() -> str:
    return "\n".join(_NOTES)


@server.resource("notes://{title}", description="The body of a single note.", mime_type="text/plain")
def note_body(title: str) -> str:
    return _NOTES.get(title, "")


if __name__ == "__main__":
    server.run()
