"""TP002: sensitive paths or secrets referenced in metadata."""

import pytest

from tests.helpers import describe, run, server, tool


@pytest.mark.parametrize(
    "text, label",
    [
        ("Reads ~/.ssh/id_rsa for you.", "SSH"),
        ("Needs your id_ed25519 file.", "SSH"),
        ("Loads the .env file first.", "environment file"),
        ("Checks .env.local too.", "environment file"),
        ("Uses ~/.aws/credentials.", "cloud credentials"),
        ("Reads ~/.config/gcloud/credentials.db", "cloud credentials"),
        ("Uses ~/.kube/config to connect.", "cloud credentials"),
        ("Opens credentials.json.", "credentials file"),
        ("Reads your .npmrc.", "credentials file"),
        ("Parses /etc/passwd.", "system account file"),
        ("Edits claude_desktop_config.json.", "agent's own configuration"),
        ("Reads ~/.cursor/mcp.json.", "agent's own configuration"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private key"),
        ("Use key AKIAIOSFODNN7EXAMPLE to sign.", "hard-coded secret"),
    ],
)
def test_fires_on_sensitive_reference(text, label):
    findings = describe("TP002", text)
    assert len(findings) == 1, text
    assert label in findings[0].message


@pytest.mark.parametrize(
    "text",
    [
        "Set environment variables for the process.",
        "Connect to a remote host over SSH.",
        "AWS region name, for example us-east-1.",
        "Path to config.json.",
        "Returns the env name and the .environment attribute.",
        "Requires an API key, passed in the api_key parameter.",
        "Manages Kubernetes deployments.",
        "Lists files in /etc and /var/log.",
    ],
)
def test_silent_on_ordinary_text(text):
    assert describe("TP002", text) == []


def test_hard_coded_secret_is_redacted_in_evidence():
    secret = "ghp_" + "a1B2c3D4e5" * 4
    findings = describe("TP002", f"Authenticate with {secret} when calling.")
    assert len(findings) == 1
    assert secret not in findings[0].evidence
    assert "redacted" in findings[0].evidence


def test_found_in_parameter_default():
    snap = server("srv", tool("t", "Fine.", path={"type": "string", "default": "~/.ssh/id_rsa"}))
    findings = run("TP002", snap)
    assert [f.pointer for f in findings] == ["/tools/0/inputSchema/properties/path/default"]
