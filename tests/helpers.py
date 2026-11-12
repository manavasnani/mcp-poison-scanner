"""Builders for rule tests: make a snapshot from a few dicts and scan it."""

from __future__ import annotations

from typing import Any

from scanner.engine import scan
from scanner.models import Finding, ServerSnapshot
from scanner.rules import STATIC_RULES, Rule


def tool(name: str = "t", description: str = "A simple tool.", **params: dict[str, Any] | str) -> dict[str, Any]:
    """A tool dict. Each keyword is a parameter: a description string or a full schema dict."""
    props = {k: ({"type": "string", "description": v} if isinstance(v, str) else v) for k, v in params.items()}
    return {"name": name, "description": description, "inputSchema": {"type": "object", "properties": props}}


def server(name: str = "srv", *tools: dict[str, Any], **extra: Any) -> ServerSnapshot:
    return ServerSnapshot(server_name=name, source="snapshot", tools=list(tools), **extra)


def rule(rule_id: str) -> Rule:
    return next(r for r in STATIC_RULES if r.id == rule_id)


def run(rule_id: str, *servers: ServerSnapshot) -> list[Finding]:
    """Findings from one rule only."""
    return scan(list(servers), rules=[rule(rule_id)])


def describe(rule_id: str, description: str) -> list[Finding]:
    """Findings from one rule on a tool with this description."""
    return run(rule_id, server("srv", tool("t", description)))


# Paraphrased descriptions in the style of widely used real servers. Nothing here is
# an attack, so no rule may fire on any of it.
BENIGN_TOOLS = [
    tool(
        "read_file",
        "Read the complete contents of a file from the file system. Handles various text encodings and "
        "provides detailed error messages if the file cannot be read. Use this tool when you need to examine "
        "the contents of a single file. Only works within allowed directories.",
        path="Absolute path of the file to read.",
    ),
    tool(
        "write_file",
        "Create a new file or completely overwrite an existing file with new content. Use with caution as it "
        "will overwrite existing files without warning.",
        path="Where to write the file.",
        content="The content to write to the file.",
    ),
    tool(
        "fetch",
        "Fetches a URL from the internet and optionally extracts its contents as markdown. Although originally "
        "you did not have internet access, and were advised to refuse and tell the user this, this tool now "
        "grants you internet access. Now you can fetch the most up-to-date information and let the user know that.",
        url="URL to fetch.",
        max_length={"type": "integer", "description": "Maximum number of characters to return.", "default": 5000},
    ),
    tool("git_status", "Shows the working tree status.", repo_path="Path to the Git repository."),
    tool(
        "create_issue",
        "Create a new issue in a GitHub repository.",
        owner="Repository owner.",
        repo="Repository name.",
        title="Issue title.",
        body="Issue body, in Markdown.",
    ),
    tool(
        "read_query",
        "Execute a SELECT query on the SQLite database. Call list_tables first if you do not know the schema.",
        query="SELECT SQL query to execute.",
    ),
    tool("list_tables", "List all tables in the SQLite database."),
    tool(
        "get_channel_history",
        "Get recent messages from a channel.",
        channel_id="The ID of the channel.",
        limit={"type": "integer", "description": "Number of recent messages to retrieve (default 10).", "default": 10},
    ),
    tool(
        "sequential_thinking",
        "A detailed tool for dynamic and reflective problem-solving through thoughts. Each thought can build on, "
        "question, or revise previous insights as understanding deepens. When to use this tool: breaking down "
        "complex problems into steps; planning with room for revision. You should start with an initial estimate "
        "of needed thoughts, feel free to question or revise previous thoughts, and only set next_thought_needed "
        "to false when truly done.",
        thought="Your current thinking step.",
        next_thought_needed={"type": "boolean", "description": "Whether another thought step is needed."},
    ),
    tool(
        "sort_results",
        "Sort search results. This is a command-line tool wrapper and should always be given a field.",
        order={"type": "string", "enum": ["asc", "desc"], "default": "asc", "description": "Sort order."},
        template={
            "type": "string",
            "description": "Summary template.",
            "default": "Summarize the following text in three bullet points.",
        },
    ),
    tool(
        "set_env",
        "Set environment variables for the process. Connects over SSH when a remote host is given.",
        region="AWS region name, for example us-east-1.",
        config="Path to config.json.",
    ),
]
