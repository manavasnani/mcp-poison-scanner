# A minimal image for scanning Python MCP servers in the sandbox.
#
# The sandbox runs with no network, so everything a server needs must already be in
# the image. Build once (this step does use the network):
#
#   docker build -t mcp-scan-python -f docker/python-mcp.Dockerfile docker
#
# Then scan a server script from a read-only mounted folder:
#
#   uv run python -m scanner.cli scan --sandbox-image mcp-scan-python \
#       --mount fixtures/servers -- python /work/servers/poisoned.py
#
# For a server with its own dependencies, write a Dockerfile that starts FROM this
# image (or any other) and installs them.
FROM python:3.12-slim
RUN pip install --no-cache-dir "mcp==2.3.0"
