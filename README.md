# vault-audit-mcp

An MCP (Model Context Protocol) server for querying Vault audit logs through a backend abstraction.

Important backend status:
- Loki is the only currently supported backend.
- The service is intentionally designed to be pluggable via the `audit.Backend` interface (`Search`, `Aggregate`, `Trace`).
- The server currently wires `LokiBackend` in `cmd/server/main.go`.

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

## Backend Architecture

`internal/audit/model.go` defines the storage abstraction:

```go
type Backend interface {
    Search(ctx context.Context, filter *SearchFilter) ([]Event, error)
    Aggregate(ctx context.Context, filter *AggregateFilter, by string) ([]Bucket, error)
    Trace(ctx context.Context, filter *TraceFilter) ([]Event, error)
}
```

Current implementation:
- `internal/audit/lokibackend.go` (`LokiBackend`)
- configured in `cmd/server/main.go` using `LOKI_URL`

Adding a new backend only requires:
1. Implementing the `Backend` interface
2. Constructing that backend in `cmd/server/main.go`
3. Providing any backend-specific configuration variables

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

Integration/diagnostic tests:

```bash
python3 test_mcp.py
```

Useful Loki checks when results are empty:

```bash
curl -s 'http://localhost:3100/loki/api/v1/query?query={service="vault"}' | jq .
curl -s 'http://localhost:3100/loki/api/v1/query?query={service="vault",log_kind="audit"}' | jq .
curl -s 'http://localhost:3100/loki/api/v1/labels' | jq .
```

## Consolidated Reference

The content previously documented in `EVENT_ANALYSIS.md`, `SUMMARIZATION.md`, and `TESTING.md` is summarized here.

### Semantic Event Analysis

Search results are semantically analyzed (not just counted). The analyzer classifies activity into categories and assigns severity levels (critical/high/medium/low/info), then emits high-signal insights for LLM consumers.

Examples of high-signal conditions:
- policy/audit/system configuration changes
- system namespace operations
- failed authentication/operation spikes

Search summaries include analysis fields such as:
- `critical_events`
- `high_risk_events`
- `event_categories`
- `key_insights`

### Summarization Strategy (Token Control)

`audit.search_events` and `audit.trace` return condensed summaries by default to keep payloads small for LLM contexts.

- `SearchSummary` includes:
  - total events and success/error stats
  - top namespaces/operations/mount types
  - success rate
  - a small sample event set
  - `summarized` flag
- `TraceSummary` includes:
  - request timeline and total events
  - first/last event context
  - namespace/operation set
  - sample events
  - `summarized` flag

`audit.aggregate` already returns compact bucketed counts and does not require additional summarization.

### Operational Troubleshooting

- No results:
  - confirm Loki has Vault audit streams and required labels
  - confirm query time window covers data
  - confirm namespace/filter values are correct
- Connection issues:
  - `curl http://localhost:3100/ready`
  - verify `LOKI_URL` and network routing
- Time parsing errors:
  - use RFC3339 timestamps (for example `2026-02-10T14:30:45Z`)

## Vault Configuration

Configure Vault audit output (example):

```hcl
audit {
  file {
    path = "stdout"
  }
}
```

Then ship logs (Promtail, etc.) to Loki and attach the labels above. An example vector.toml is provided.

## Data Sensitivity

Returned events are redacted in code before response. Current redaction includes:

- Top-level `error` / `errors`
- `auth.client_token`, `auth.accessor`, `auth.secret_id`, `auth.metadata`
- `response.auth.client_token`, `response.auth.accessor`, `response.auth.secret_id`
- `response.secret.data`
- `response.wrap_info`
- `request.data`

Other fields (for example path, operation, namespace, mount metadata, and some response fields) may be preserved for analysis.

## Security Disclaimer

Vault audit logs should be treated as sensitive data. They can contain security-relevant metadata and potentially sensitive operational context.

Protecting audit log access is critical. Apply strong authentication, authorization, transport security, and storage controls in your logging and observability stack.

This project does not provide any built-in mechanism for securing access to audit logs or backend storage providers. Access control and data protection are the responsibility of your surrounding infrastructure and platform configuration.
