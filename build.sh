#!/bin/bash
# Test script for vault-audit-mcp

set -e

LOKI_URL="${LOKI_URL:-http://localhost:3100}"
BINARY="${1:-.server}"

echo "🔨 Building server..."
go build -o "$BINARY" ./cmd/server

echo "✅ Build successful"
echo ""
echo "📋 To test the server, you can:"
echo ""
echo "1. Run the server in the background:"
echo "   LOKI_URL=$LOKI_URL ./$BINARY &"
echo ""
echo "2. Test with curl (raw JSON over stdin):"
echo "   Example: Send a search_events request"
echo ""
echo "3. Or use an MCP client like Claude Desktop"
echo ""
echo "🚀 Quick start:"
echo "   LOKI_URL=$LOKI_URL ./$BINARY"
echo ""
