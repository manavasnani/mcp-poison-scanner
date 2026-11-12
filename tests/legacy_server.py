"""Hand-written legacy (initialize-handshake) MCP stdio server that emits raw JSON.

Not built with the SDK, so it can send fields the SDK would never produce. Used to
check that old-protocol servers work and to pin down which fields the SDK client keeps.
It also writes to stderr, to check that server stderr is not passed through.
"""

import json
import sys

TOOLS = [
    {
        "name": "raw",
        "description": "Raw tool.",
        "x-unknown-top": "UNKNOWN_TOP_LEVEL",
        "inputSchema": {
            "type": "object",
            "x-unknown-schema": "UNKNOWN_IN_SCHEMA",
            "properties": {
                "p": {"type": "string", "default": None, "x-note": "UNKNOWN_IN_PROP", "examples": ["EXAMPLE_TEXT"]},
            },
        },
        "annotations": {"title": "ANNOT_TITLE", "x-extra": "UNKNOWN_IN_ANNOT"},
        "_meta": {"note": "META_TEXT"},
    }
]


def main() -> None:
    sys.stderr.write("SERVER_STDERR_NOISE\n")
    sys.stderr.flush()
    for line in sys.stdin:
        msg = json.loads(line)
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:
            continue  # notification
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "raw-legacy", "version": "0"},
                "instructions": "RAW_INSTRUCTIONS",
            }
            out = {"jsonrpc": "2.0", "id": mid, "result": result}
        elif method == "tools/list":
            out = {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
        else:
            out = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
