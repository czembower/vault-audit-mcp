#!/bin/bash

# Test the audit.search_events tool directly
(
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}'
  sleep 0.5
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"audit.search_events","arguments":{"mount_class":"auth","start_rfc3339":"2026-02-11T13:47:00Z","end_rfc3339":"2026-02-11T14:47:00Z","limit":10}}}'
  sleep 2
) | AUDIT_DEBUG_LOG=1 LOKI_URL=http://localhost:3100 ./vault-audit-mcp 2>&1
