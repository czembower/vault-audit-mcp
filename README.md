# vault-audit-mcp

An MCP (Model Context Protocol) server for querying Vault audit logs stored in Loki.

## Features

- **Search Events**: Query Vault audit events by namespace, operation, mount type, and status
- **Aggregate**: Count events grouped by any dimension (namespace/operation/mount_type/status)
- **Trace**: Follow a specific request ID through audit logs

## Prerequisites

- Vault configured with Loki as an audit backend
- Loki instance receiving Vault audit logs with labels:
  - `service=vault`
  - `log_kind=audit`
  - `vault_namespace` (e.g., `root`, `team-a/`)
  - `vault_operation` (e.g., `create`, `read`, `update`, `delete`)
  - `vault_mount_type` (e.g., `pki`, `kv`, `userpass`)
  - `vault_status` (e.g., `ok`, `error`)

## Building

```bash
go build -o server ./cmd/server
```

## Running

Set the Loki URL (defaults to `http://localhost:3100`):

```bash
LOKI_URL=http://localhost:3100 ./server
```

The server uses stdio transport and is ready to be used with MCP clients (Claude Desktop, etc).

## Configuration

### Environment Variables

- `LOKI_URL` - Loki API endpoint (default: `http://localhost:3100`)

## Tools

### audit.search_events

Search Vault audit events by label filters.

**Parameters:**
- `start_rfc3339` - Start time (RFC3339, defaults to now-15m)
- `end_rfc3339` - End time (RFC3339, defaults to now)
- `limit` - Max results (1-500, default 100)
- `namespace` - Filter by Vault namespace
- `operation` - Filter by operation type
- `mount_type` - Filter by mount type
- `status` - Filter by status (ok or error)

### audit.aggregate

Count events grouped by a dimension.

**Parameters:**
- `start_rfc3339` - Start time (RFC3339, defaults to now-15m)
- `end_rfc3339` - End time (RFC3339, defaults to now)
- `by` - Aggregation dimension (vault_namespace, vault_operation, vault_mount_type, or vault_status)
- `namespace`, `operation`, `mount_type`, `status` - Optional filters

### audit.trace

Find all events for a specific request ID.

**Parameters:**
- `start_rfc3339` - Start time (RFC3339, defaults to now-15m)
- `end_rfc3339` - End time (RFC3339, defaults to now)
- `limit` - Max results (default 100)
- `request_id` - Vault request ID to trace (required)

## Testing

### Build and Run

```bash
go build -o server ./cmd/server
LOKI_URL=http://localhost:3100 ./server
```

### Run Tests

```bash
go test ./internal/audit -v
```

## Vault Configuration

Configure Vault to send audit logs to Loki. Example with JSON formatting:

```hcl
audit {
  file {
    path = "stdout"
  }
}
```

Then pipe Vault logs through a log shipper (Promtail, Logstash, etc.) with appropriate labels.

## Data Sensitivity

All returned events are automatically redacted to remove:
- Authentication tokens and accessors
- Secret IDs
- Request/response bodies containing sensitive data
- Error messages with secret references

Non-sensitive fields like paths, operations, and namespaces are preserved for analysis.