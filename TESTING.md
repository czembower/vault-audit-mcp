# Testing the Vault Audit MCP Server

This guide shows you how to test queries against the MCP server and diagnose why you might not be seeing audit events.

## Quick Start

### 1. Run the Comprehensive Test

The easiest way to verify everything is working:

```bash
cd vault-audit-mcp
python3 test_mcp.py
```

This tests all three tools: `search_events`, `aggregate`, and `trace`.

## Understanding Empty Results

If all your queries return empty results, check these things in order:

### 1. Verify Loki Has Audit Data

Check if your Loki instance actually has any Vault audit events:

```bash
# Query Loki directly for any Vault logs
curl -s 'http://localhost:3100/loki/api/v1/query?query={service="vault"}' | jq .

# Or specifically for audit logs
curl -s 'http://localhost:3100/loki/api/v1/query?query={service="vault",log_kind="audit"}' | jq .
```

Expected response should have non-empty `values` array in `result.streams[].values`.

### 2. Check Vault Audit Configuration

Verify Vault is configured to send audit logs to Loki:

```bash
# Check audit devices in Vault
vault audit list

# Should show something like:
# Path         Type       Description
# ----         ----       -----------
# file/        file       
# syslog/      syslog     
```

### 3. Verify Required Labels

Vault audit logs must have these labels in Loki:
- `service=vault` - Identifies as Vault logs
- `log_kind=audit` - Identifies as audit (not request/response)
- `vault_namespace` - The Vault namespace
- `vault_operation` - The operation (create, read, update, delete, list, etc.)
- `vault_mount_type` - The mount type (pki, secret, auth, etc.)
- `vault_status` - ok or error

Check what labels actually exist in Loki:

```bash
# Get all label names
curl -s 'http://localhost:3100/loki/api/v1/labels' | jq .

# Get values for a specific label
curl -s 'http://localhost:3100/loki/api/v1/label/vault_operation/values' | jq .
```

## Testing Individual Tools

### 1. Search Events

Find all audit events in a time range:

```bash
cat > /tmp/search_query.json << 'EOF'
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "audit.search_events",
    "arguments": {
      "limit": 10,
      "namespace": "root"
    }
  }
}
EOF

cat /tmp/search_query.json | nc localhost 9000
```

**Parameters:**
- `start_rfc3339`: Start time (RFC3339). Defaults to now-15m.
- `end_rfc3339`: End time (RFC3339). Defaults to now.
- `limit`: Max number of events (1-500, default 100)
- `namespace`: Filter by Vault namespace (optional)
- `operation`: Filter by operation (optional)
- `mount_type`: Filter by mount type (optional)
- `status`: Filter by status - "ok" or "error" (optional)

### 2. Aggregate Events

Count events grouped by a dimension:

```bash
cat > /tmp/aggregate_query.json << 'EOF'
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "audit.aggregate",
    "arguments": {
      "by": "vault_operation",
      "namespace": "root"
    }
  }
}
EOF
```

**Parameters:**
- `by`: Required - group by one of: `vault_namespace`, `vault_operation`, `vault_mount_type`, `vault_status`
- `start_rfc3339`: Start time (RFC3339). Defaults to now-15m.
- `end_rfc3339`: End time (RFC3339). Defaults to now.
- Plus optional filters: `namespace`, `operation`, `mount_type`, `status`

**Returns:**
- Array of `{ name: string, count: int }` objects showing counts per dimension value

### 3. Trace by Request ID

Find all events for a specific Vault request:

```bash
cat > /tmp/trace_query.json << 'EOF'
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "audit.trace",
    "arguments": {
      "request_id": "some-vault-request-id-12345"
    }
  }
}
EOF
```

**Parameters:**
- `request_id`: Required - The Vault request ID to trace
- `start_rfc3339`: Start time (RFC3339). Defaults to now-15m.
- `end_rfc3339`: End time (RFC3339). Defaults to now.
- `limit`: Max number of events (default 100)

## Generate Real Vault Audit Traffic

To test with actual Vault operations:

```bash
# Set up Vault client
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=hvs.your-token

# Generate some audit traffic
vault kv put secret/test key=value
vault kv get secret/test
vault kv delete secret/test

# Then query the MCP server
python3 test_mcp.py
```

## Integration with Claude Desktop

Once you have working queries, configure Claude Desktop to use this MCP server:

1. Copy the server to a known location:
   ```bash
   cp ./server ~/bin/vault-audit-server
   chmod +x ~/bin/vault-audit-server
   ```

2. Update `~/Library/Application Support/Claude/claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "vault-audit": {
         "command": "env",
         "args": [
           "LOKI_URL=http://localhost:3100",
           "PATH=$PATH",
           "/usr/local/bin/vault-audit-server"
         ]
       }
     }
   }
   ```

3. Restart Claude Desktop and ask it to search your Vault audit logs!

## Data Redaction

For security, the MCP server automatically redacts sensitive fields:
- `auth.client_token` → redacted
- `auth.accessor` → redacted
- `auth.secret_id` → redacted
- `response.secret.data` → redacted
- `request.data` → redacted
- `wrap_info` → redacted

Non-sensitive fields like paths, operations, and status are preserved.

## Troubleshooting

**Server exits immediately:**
```bash
LOKI_URL=http://localhost:3100 ./server 2>&1
# Watch for connection errors to Loki
```

**Empty results but data exists in Loki:**
- Check label names match exactly (case-sensitive)
- Verify time range covers when logs were written
- Check Vault namespace matches (if using Vault Enterprise)

**Getting "invalid time format" errors:**
- Use RFC3339 format: `2024-02-10T14:30:45Z`
- Or use ISO8601: `2024-02-10T14:30:45+00:00`

**Loki connection refused:**
- Verify Loki is running: `curl http://localhost:3100/ready`
- Check firewall rules
- Verify LOKI_URL environment variable
