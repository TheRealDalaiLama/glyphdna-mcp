FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 openssl mosquitto-clients ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY mcp_glyphdna.py .

# stdio MCP server: starts immediately, responds to tools/list without network access
ENTRYPOINT ["python3", "mcp_glyphdna.py"]
