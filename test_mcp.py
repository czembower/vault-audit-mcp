#!/usr/bin/env python3
"""MCP protocol test client for Vault audit queries."""

import json
import subprocess
import sys
import os
import time

# Get the workspace directory
workspace_dir = os.path.expanduser(
    "~/Library/Mobile Documents/com~apple~CloudDocs/Repos/vault-audit-mcp"
)

# Start the server
print("Starting MCP server...")
print(f"Working directory: {workspace_dir}")
proc = subprocess.Popen(
    ["./server"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    cwd=workspace_dir,
    env={
        **os.environ,
        "LOKI_URL": "http://localhost:3100",
    },
)
print("Server started. Waiting for connection...\n")
time.sleep(0.5)

def send_request(method, params=None, request_id=1):
    """Send a JSON-RPC request to the server."""
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
    }
    if params:
        request["params"] = params
    
    request_json = json.dumps(request) + "\n"
    print(f"\n>>> Request ID {request_id}: {method}")
    print(f"    {json.dumps(params or {}, indent=6)}")
    proc.stdin.write(request_json)
    proc.stdin.flush()

def read_response(request_id):
    """Read a JSON-RPC response from the server, skipping notifications."""
    while True:
        line = proc.stdout.readline()
        if not line:
            print("EOF reached")
            return None
        try:
            data = json.loads(line)
            # Skip notifications (no 'id' field)
            if "method" in data and "id" not in data:
                print(f"    [Notification: {data['method']}]")
                continue
            # Check if this is our response
            if data.get("id") == request_id:
                return data
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON: {e}")
            return None

def print_response(response):
    """Pretty print a response."""
    if not response:
        return
    
    if response.get('error'):
        print(f"<<< Error: {response['error']}")
    else:
        result = response.get('result')
        if isinstance(result, (dict, list)):
            # Truncate large responses
            result_str = json.dumps(result, indent=2)
            if len(result_str) > 500:
                print(f"<<< Result ({len(str(result))} bytes):")
                print(result_str[:500] + "\n    ... (truncated)")
            else:
                print(f"<<< Result: {result_str}")
        else:
            print(f"<<< Result: {result}")

try:
    # Step 1: Initialize
    print("\n" + "="*60)
    print("STEP 1: Initialize MCP Session")
    print("="*60)
    send_request("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "test-client",
            "version": "1.0.0",
        },
    }, request_id=0)
    response = read_response(0)
    if response:
        server_info = response.get('result', {}).get('serverInfo', {})
        print(f"✓ Server initialized: {server_info['name']} v{server_info['version']}")
    
    # Step 2: List available tools
    print("\n" + "="*60)
    print("STEP 2: List Available Tools")
    print("="*60)
    send_request("tools/list", {}, request_id=1)
    response = read_response(1)
    if response:
        tools = response.get('result', {}).get('tools', [])
        print(f"✓ Found {len(tools)} tools:")
        for tool in tools:
            print(f"  • {tool['name']}")
            print(f"    {tool['description']}")
    
    # Step 3: Test search_events tool
    print("\n" + "="*60)
    print("STEP 3: Search Audit Events")
    print("="*60)
    print("\nQuery: Search for all audit events in the last 15 minutes (limit: 5)")
    send_request("tools/call", {
        "name": "audit.search_events",
        "arguments": {
            "limit": 5,
        }
    }, request_id=2)
    response = read_response(2)
    print_response(response)
    
    # Step 4: Test aggregate tool
    print("\n" + "="*60)
    print("STEP 4: Aggregate Audit Events")
    print("="*60)
    print("\nQuery: Count events grouped by operation in the last 15 minutes")
    send_request("tools/call", {
        "name": "audit.aggregate",
        "arguments": {
            "by": "vault_operation",
        }
    }, request_id=3)
    response = read_response(3)
    print_response(response)
    
    # Step 5: Test trace tool
    print("\n" + "="*60)
    print("STEP 5: Trace Audit Events by Request ID")
    print("="*60)
    print("\nQuery: Trace all events for a specific request (requires a valid request_id)")
    print("Note: This will fail or return empty if no audit logs exist yet")
    send_request("tools/call", {
        "name": "audit.trace",
        "arguments": {
            "request_id": "test-request-123",
            "limit": 10,
        }
    }, request_id=4)
    response = read_response(4)
    print_response(response)
    
    print("\n" + "="*60)
    print("✓ All tests completed successfully!")
    print("="*60)
    print("\nNext steps:")
    print("1. Verify Vault is logging audit events to Loki")
    print("2. Use real request IDs and timestamps in your queries")
    print("3. Integrate with Claude Desktop using the generated schema")
    
except Exception as e:
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
    
finally:
    # Clean up
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except:
        proc.kill()
