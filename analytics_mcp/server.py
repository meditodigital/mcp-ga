#!/usr/bin/env python

# Copyright 2025 Google LLC All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Entry point for the Google Analytics MCP server."""

import asyncio
import os
import sys
import analytics_mcp.coordinator as coordinator
from mcp.server.lowlevel import NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.server


async def run_server_async():
    """Runs the MCP server over standard I/O."""
    print("Starting MCP Stdio Server:", coordinator.app.name, file=sys.stderr)
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await coordinator.app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name=coordinator.app.name,  # Use the server name defined above
                server_version="1.0.0",
                capabilities=coordinator.app.get_capabilities(
                    # Define server capabilities - consult MCP docs for options
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def run_server():
    """Runs the MCP server using stdio or Streamable HTTP."""
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        asyncio.run(run_server_async())
        return
    if transport in {"streamable-http", "remote-http"}:
        from analytics_mcp.web_app import run_web_app

        run_web_app(coordinator.app)
        return
    raise ValueError(
        f"Unknown MCP_TRANSPORT '{transport}'. Use 'stdio' or 'streamable-http'."
    )


if __name__ == "__main__":
    try:
        run_server()
    except KeyboardInterrupt:
        print("\nMCP Server stopped by user.", file=sys.stderr)
    except Exception:
        import traceback

        print("MCP Server encountered an error:", file=sys.stderr)
        traceback.print_exc()
    finally:
        print("MCP Server process exiting.", file=sys.stderr)
