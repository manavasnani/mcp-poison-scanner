# Image holding widely used MCP servers, for collecting their tool lists (the clean set).
#
# Building downloads third-party packages and runs their install scripts, inside the
# build container only. The servers themselves are later run by the scanner's sandbox:
# no network, read-only filesystem, unprivileged user.
#
#   docker build -t mcp-bench-servers benchmarks/clean_servers
#   uv run python -m benchmarks.collect_clean
#
# Versions are not pinned here; the collect step records what was installed.
FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin UV_PYTHON_INSTALL_DIR=/opt/python \
    PUPPETEER_SKIP_DOWNLOAD=1 PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm_config_update_notifier=false

# One package per step, each allowed to fail: a broken package should not sink the rest.
RUN for pkg in \
      @modelcontextprotocol/server-filesystem \
      @modelcontextprotocol/server-memory \
      @modelcontextprotocol/server-sequential-thinking \
      @modelcontextprotocol/server-everything \
      @modelcontextprotocol/server-github \
      @modelcontextprotocol/server-gitlab \
      @modelcontextprotocol/server-postgres \
      @modelcontextprotocol/server-brave-search \
      @modelcontextprotocol/server-slack \
      @modelcontextprotocol/server-google-maps \
      @modelcontextprotocol/server-redis \
      @modelcontextprotocol/server-puppeteer \
      @playwright/mcp \
      @upstash/context7-mcp \
      @notionhq/notion-mcp-server \
      firecrawl-mcp \
      tavily-mcp \
      exa-mcp-server \
    ; do npm install -g --no-audit --no-fund "$pkg" || echo "INSTALL FAILED: $pkg" >> /install-failures.txt; done; \
    touch /install-failures.txt

RUN for pkg in mcp-server-fetch mcp-server-git mcp-server-time mcp-server-sqlite; do \
      uv tool install --python 3.12 "$pkg" || echo "INSTALL FAILED: $pkg" >> /install-failures.txt; done

# What actually got installed, for the benchmark record.
RUN (npm ls -g --depth=0 2>/dev/null; uv tool list 2>/dev/null) > /installed-versions.txt; \
    chmod -R a+rX /opt /usr/local/lib/node_modules
