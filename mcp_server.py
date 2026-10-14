#!/usr/bin/env python3
"""
NetWarden MCP Server Entrypoint.
Usage:
    python mcp_server.py                # Runs over stdio (default for Claude Desktop, Cursor, AGY)
    python mcp_server.py --transport sse --port 8000 # Runs over SSE for remote / containerized agents
"""

import sys
import argparse
from netwarden.server import app


def main():
    parser = argparse.ArgumentParser(description="NetWarden Multi-Brand Network Management MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind for HTTP/SSE transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind for HTTP/SSE transport (default: 8000)",
    )

    args = parser.parse_args()

    if args.transport == "stdio":
        app.run(transport="stdio")
    else:
        app.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
