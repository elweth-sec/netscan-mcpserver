#!/usr/bin/env python3
"""
MCP Server for netscan — https://github.com/hegusung/netscan (branch: dev)

Environment variables:
  NETSCAN_PATH         Path to the netscan binary  (default: "netscan")
  NETSCAN_SCAN_TIMEOUT Max seconds to wait per scan (default: 600)
"""
import netscan.scanners  # noqa: F401 — triggers auto-discovery of all @mcp.tool()s
from netscan import mcp

if __name__ == "__main__":
    mcp.run()
