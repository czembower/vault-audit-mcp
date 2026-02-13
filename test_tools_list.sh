#!/bin/bash

# Test tools/list to see all registered tools
(
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}'
  sleep 0.5
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  sleep 1
) | LOKI_URL=http://localhost:3100 ./vault-audit-mcp 2>&1
