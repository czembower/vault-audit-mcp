# vault-audit-mcp

An MCP (Model Context Protocol) server for querying Vault audit logs from a pluggable backend provider. At present, the only supported storage backend is Loki, but intention is to develop adapters for Splunk and Elasticsearch next.

## Features

- Search Vault audit events with label-based filters
- Aggregate event counts by label dimensions
- Trace all events for a Vault request ID
- Retrieve detailed events for a request ID

## Prerequisites (Loki-specific)

- Vault configured with an audit device that ships logs to Loki
- Loki instance receiving Vault audit logs with these baseline labels:
  - `service=vault`
  - `log_kind=audit`

For full filtering support, ensure these labels are also present:

- `vault_namespace` (e.g., `root`, `team-a/`)
- `vault_operation` (e.g., `create`, `read`, `update`, `delete`)
- `vault_mount_type` (e.g., `pki`, `kv`, `userpass`)
- `vault_status` (e.g., `ok`, `error`)
- `vault_mount_class` (e.g., `auth`, `secret`, `system`)
- `vault_entity_id`
- `vault_policies` (comma-separated)
- `vault_token_policies` (comma-separated)

## Building

```bash
go build -o server ./cmd/server
```

## Running

Set Loki URL (defaults to `http://localhost:3100`):

```bash
LOKI_URL=http://localhost:3100 ./server
```

The server uses stdio transport and is ready for MCP clients.

## Configuration

### Environment Variables

- `LOKI_URL` - Loki API endpoint (default: `http://localhost:3100`)
- `AUDIT_DEBUG_LOG` - Enable debug query logging (`1` or `true`)

## Tools

### `audit.search_events`

Search Vault audit events. Returns a summarized result (statistics, top dimensions, key insights, and sample events).

Parameters:
- `start_rfc3339` - Start time (RFC3339, defaults to now-15m)
- `end_rfc3339` - End time (RFC3339, defaults to now)
- `limit` - Max results (1-500, default 100)
- `namespace` - Filter by namespace
- `operation` - Filter by operation (supports special handling for `login` and write/update aliasing)
- `mount_type` - Filter by mount type
- `mount_class` - Filter by mount class
- `status` - Filter by status (`ok` or `error`)
- `policy` - Filter by policy name (matches both `vault_policies` and `vault_token_policies`)
- `entity_id` - Filter by entity ID

### `audit.aggregate`

Count events grouped by a dimension.

Parameters:
- `start_rfc3339` - Start time (RFC3339, defaults to now-15m)
- `end_rfc3339` - End time (RFC3339, defaults to now)
- `by` - Aggregation dimension
  - Currently supported at runtime: `vault_namespace`, `vault_operation`, `vault_mount_type`, `vault_status`
  - Note: `vault_mount_class` exists in the tool schema but is currently rejected by backend validation
- Optional filters: `namespace`, `operation`, `mount_type`, `mount_class`, `status`

### `audit.trace`

Find events for a specific request ID over a time range. Returns a summarized timeline.

Parameters:
- `start_rfc3339` - Start time (RFC3339, defaults to now-15m)
- `end_rfc3339` - End time (RFC3339, defaults to now)
- `limit` - Max results (default 100, max 500)
- `request_id` - Vault request ID (required)

### `audit.get_event_details`

Retrieve detailed events for a request ID.

Parameters:
- `request_id` - Vault request ID (required)

Notes:
- Looks back over the last 24 hours
- Returns detailed event objects (including redacted `raw` audit payload)

## Testing

```bash
go test ./internal/audit -v
```

## Vault Configuration

Configure Vault audit output (example):

```hcl
audit {
  file {
    path = "stdout"
  }
}
```

Then ship logs (Promtail, etc.) to Loki and attach the labels above.

## Data Sensitivity

Returned events are redacted in code before response. Current redaction includes:

- Top-level `error` / `errors`
- `auth.client_token`, `auth.accessor`, `auth.secret_id`, `auth.metadata`
- `response.auth.client_token`, `response.auth.accessor`, `response.auth.secret_id`
- `response.secret.data`
- `response.wrap_info`
- `request.data`

Other fields (for example path, operation, namespace, mount metadata, and some response fields) may be preserved for analysis.
