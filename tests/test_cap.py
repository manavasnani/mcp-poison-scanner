"""CAP001 (toxic capability combination) and CAP002 (over-broad capability)."""

import pytest

from scanner.capabilities import Capability, profile_tool
from tests.helpers import BENIGN_TOOLS, run, server, tool

READ = tool("read_file", "Read the contents of a file. Only works within allowed directories.", path="File to read.")
FETCH = tool("fetch", "Fetches a URL from the internet and returns its contents as markdown.", url="URL to fetch.")
SEND = tool("send_email", "Send an email to a recipient.", to="Recipient address.", body="Message text.")
INBOX = tool("list_inbox", "List the newest emails in the user's inbox.")
SEARCH = tool("web_search", "Search the web and return the top results.", query="Search terms.")
NOTES = tool("add_note", "Save a note under a title.", title="Note title.", body="Note text.")


def caps(t: dict) -> set[Capability]:
    return set(profile_tool("srv", 0, t).capabilities)


# --- capability classification ----------------------------------------------------------------


@pytest.mark.parametrize(
    "t, expected",
    [
        (READ, {Capability.READS_PRIVATE}),
        (FETCH, {Capability.UNTRUSTED_INPUT, Capability.SENDS_OUT}),
        (SEND, {Capability.SENDS_OUT}),
        (INBOX, {Capability.READS_PRIVATE, Capability.UNTRUSTED_INPUT}),
        (SEARCH, {Capability.UNTRUSTED_INPUT}),
        (tool("run_command", "Run any shell command on the host."), {Capability.EXECUTES_CODE}),
        (tool("execute", "Executes arbitrary Python code in a subprocess."), {Capability.EXECUTES_CODE}),
        (tool("readQuery", "Execute a SELECT query on the database."), {Capability.READS_PRIVATE}),
        (tool("createIssue", "Create a new issue in a GitHub repository."), {Capability.SENDS_OUT}),
        (NOTES, set()),
        (tool("add", "Add two numbers."), set()),
        (tool("get_weather", "Get the current weather for a city."), set()),
        (tool("git_status", "Shows the working tree status.", repo_path="Path to the Git repository."), set()),
    ],
)
def test_capabilities_from_name_and_description(t, expected):
    assert caps(t) == expected


def test_capabilities_survive_missing_or_odd_fields():
    assert caps({"name": "t"}) == set()
    assert caps({"description": 5, "inputSchema": "nope"}) == set()
    assert caps({"name": "run_shell", "inputSchema": {"properties": ["not", "a", "dict"]}}) == set()


# --- CAP001 -------------------------------------------------------------------------------------


def test_cap001_fires_when_one_server_has_all_three_legs():
    findings = run("CAP001", server("srv", NOTES, READ, FETCH))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert (finding.item_name, finding.pointer) == ("fetch", "/tools/2")  # anchored on the tool that sends out
    assert "srv/read_file" in finding.evidence and "srv/fetch" in finding.evidence


def test_cap001_combines_tools_across_servers():
    files = server("files", READ)
    web = server("web", SEARCH)
    mail = server("mail", SEND)
    findings = run("CAP001", files, web, mail)
    assert [(f.server, f.item_name) for f in findings] == [("mail", "send_email")]
    for name in ("files/read_file", "web/web_search", "mail/send_email"):
        assert name in findings[0].evidence


def test_cap001_reports_once_however_many_tools_qualify():
    many = [tool(f"send_{i}", "Send a message to a channel.") for i in range(6)]
    findings = run("CAP001", server("srv", READ, FETCH, *many))
    assert len(findings) == 1
    assert "more" in findings[0].evidence


@pytest.mark.parametrize(
    "tools",
    [
        [READ, SEND],  # nothing brings untrusted content in
        [READ, SEARCH],  # nothing sends data out
        [SEARCH, SEND],  # nothing private to steal
        [NOTES],
        [],
    ],
)
def test_cap001_silent_when_a_leg_is_missing(tools):
    assert run("CAP001", server("srv", *tools)) == []


def test_cap001_fires_on_a_typical_real_world_config():
    # Honest tools, dangerous together: this is what CAP001 exists to point out.
    assert len(run("CAP001", server("popular", *BENIGN_TOOLS))) == 1


# --- CAP002 -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "t",
    [
        tool("run_command", "Run any shell command on the host and return its output.", command="Command."),
        tool("exec", "Executes a bash script.", script="Script body."),
        tool("python", "Run arbitrary code in the interpreter.", code="Source."),
    ],
)
def test_cap002_fires_on_command_execution(t):
    findings = run("CAP002", server("srv", t))
    assert [f.pointer for f in findings] == ["/tools/0/description"]
    assert findings[0].severity == "medium"
    assert "runs commands or code" in findings[0].message


def test_cap002_fires_on_unrestricted_file_path():
    write = tool("write_file", "Create a new file or overwrite an existing file.", path="Where to write.", content="x")
    findings = run("CAP002", server("srv", write))
    assert [f.pointer for f in findings] == ["/tools/0/inputSchema/properties/path"]
    assert "any file path" in findings[0].message


def test_cap002_fires_on_arbitrary_url_fetch():
    findings = run("CAP002", server("srv", FETCH))
    assert [f.pointer for f in findings] == ["/tools/0/inputSchema/properties/url"]
    assert "any URL" in findings[0].message


@pytest.mark.parametrize(
    "t",
    [
        READ,  # says it only works within allowed directories
        tool("read_doc", "Read a file from the workspace.", path="Path relative to the project root."),
        tool("fetch_docs", "Fetch a page. Only allowed domains can be reached.", url="Page URL."),
        tool("open_site", "Open one of the supported sites.", url={"type": "string", "enum": ["https://a.example"]}),
        tool("git_status", "Shows the working tree status.", repo_path="Path to the Git repository."),
        tool("set_env", "Set environment variables for the process.", config="Path to config.json."),
        tool("read_query", "Execute a SELECT query on the SQLite database.", query="SQL."),
        tool("link_account", "Store the user's profile link.", url="Profile URL."),  # takes a URL, fetches nothing
        SEND,
        NOTES,
    ],
)
def test_cap002_silent_on_limited_or_ordinary_tools(t):
    assert run("CAP002", server("srv", t)) == []


def test_cap002_reports_each_broad_tool_separately():
    shell = tool("shell", "Run a shell command.", command="Command.")
    findings = run("CAP002", server("a", shell), server("b", FETCH))
    assert sorted((f.server, f.item_name) for f in findings) == [("a", "shell"), ("b", "fetch")]


def test_cap_findings_escape_hostile_names():
    esc = chr(0x1B)
    bad = tool(f"run{esc}[2J_command", "Run any shell command.", **{f"u{esc}rl": "x"})
    for finding in run("CAP002", server(f"s{esc}", bad)):
        assert esc not in finding.message and esc not in finding.evidence
