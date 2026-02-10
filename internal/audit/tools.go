package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Service provides audit trail functionality through registered MCP tools.
type Service struct {
	backend Backend
}

// NewService creates a new audit service with the given backend.
func NewService(backend Backend) *Service {
	if backend == nil {
		panic("backend cannot be nil")
	}
	return &Service{backend: backend}
}

// SearchArgs defines parameters for the search_events tool.
type SearchArgs struct {
	StartRFC3339 string `json:"start_rfc3339,omitempty" jsonschema:"Start time (RFC3339). Defaults to now-15m."`
	EndRFC3339   string `json:"end_rfc3339,omitempty" jsonschema:"End time (RFC3339). Defaults to now."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Max number of log lines to return. Max 500, default 100."`

	Namespace string `json:"namespace,omitempty" jsonschema:"Vault namespace path label value, e.g. myNamespace/"`
	Operation string `json:"operation,omitempty" jsonschema:"Vault operation label value, e.g. update"`
	MountType string `json:"mount_type,omitempty" jsonschema:"Vault mount type label value, e.g. pki"`
	Status    string `json:"status,omitempty" jsonschema:"ok or error"`
}

// AggregateArgs defines parameters for the aggregate tool.
type AggregateArgs struct {
	StartRFC3339 string `json:"start_rfc3339,omitempty" jsonschema:"Start time (RFC3339). Defaults to now-15m."`
	EndRFC3339   string `json:"end_rfc3339,omitempty" jsonschema:"End time (RFC3339). Defaults to now."`
	By           string `json:"by" jsonschema:"One of: vault_namespace, vault_operation, vault_mount_type, vault_status"`
	// Optional filters:
	Namespace string `json:"namespace,omitempty" jsonschema:"Filter by namespace."`
	Operation string `json:"operation,omitempty" jsonschema:"Filter by operation."`
	MountType string `json:"mount_type,omitempty" jsonschema:"Filter by mount type."`
	Status    string `json:"status,omitempty" jsonschema:"Filter by status (ok or error)."`
}

// TraceArgs defines parameters for the trace tool.
type TraceArgs struct {
	StartRFC3339 string `json:"start_rfc3339,omitempty" jsonschema:"Start time (RFC3339). Defaults to now-15m."`
	EndRFC3339   string `json:"end_rfc3339,omitempty" jsonschema:"End time (RFC3339). Defaults to now."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Max number of log lines to return. Default 100."`
	RequestID    string `json:"request_id" jsonschema:"Vault request id (request.id) to trace"`
}

// parseRange parses start and end time strings, returning defaults if not provided.
func parseRange(startStr, endStr string) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	end := now
	start := now.Add(-DefaultQueryAge)

	if endStr != "" {
		t, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid end time: %w", err)
		}
		end = t.UTC()
	}
	if startStr != "" {
		t, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid start time: %w", err)
		}
		start = t.UTC()
	}

	// Validate time range logic
	if start.After(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("start time cannot be after end time")
	}

	return start, end, nil
}

// AddTools registers all audit tools with the MCP server.
func (s *Service) AddTools(server *mcp.Server) {
	// audit.search_events
	mcp.AddTool(server, &mcp.Tool{
		Name:        "audit.search_events",
		Description: "Search Vault audit events by labels (namespace, operation, mount type, status). Returns redacted, structured events with best-effort field extraction.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args SearchArgs) (*mcp.CallToolResult, any, error) {
		start, end, err := parseRange(args.StartRFC3339, args.EndRFC3339)
		if err != nil {
			return nil, nil, err
		}

		filter := &SearchFilter{
			Start:     start,
			End:       end,
			Limit:     args.Limit,
			Namespace: args.Namespace,
			Operation: args.Operation,
			MountType: args.MountType,
			Status:    args.Status,
		}

		events, err := s.backend.Search(ctx, filter)
		if err != nil {
			return nil, nil, err
		}

		return nil, events, nil
	})

	// audit.aggregate
	mcp.AddTool(server, &mcp.Tool{
		Name:        "audit.aggregate",
		Description: "Aggregate Vault audit events by counting events grouped by a dimension (namespace, operation, mount_type, or status).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args AggregateArgs) (*mcp.CallToolResult, any, error) {
		start, end, err := parseRange(args.StartRFC3339, args.EndRFC3339)
		if err != nil {
			return nil, nil, err
		}

		// Validate 'by' parameter is one of the valid dimensions
		byLabel := args.By
		switch byLabel {
		case LabelNamespace, LabelOperation, LabelMountType, LabelStatus:
			// Valid dimension, use as-is
		default:
			return nil, nil, fmt.Errorf("invalid 'by' parameter: %q, must be one of: vault_namespace, vault_operation, vault_mount_type, vault_status", args.By)
		}

		filter := &AggregateFilter{
			Start:     start,
			End:       end,
			Namespace: args.Namespace,
			Operation: args.Operation,
			MountType: args.MountType,
			Status:    args.Status,
		}

		buckets, err := s.backend.Aggregate(ctx, filter, byLabel)
		if err != nil {
			return nil, nil, err
		}

		return nil, buckets, nil
	})

	// audit.trace
	mcp.AddTool(server, &mcp.Tool{
		Name:        "audit.trace",
		Description: "Trace all audit events for a specific Vault request ID across the time range.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args TraceArgs) (*mcp.CallToolResult, any, error) {
		start, end, err := parseRange(args.StartRFC3339, args.EndRFC3339)
		if err != nil {
			return nil, nil, err
		}

		if args.RequestID == "" {
			return nil, nil, fmt.Errorf("request_id is required")
		}

		filter := &TraceFilter{
			Start:     start,
			End:       end,
			Limit:     args.Limit,
			RequestID: args.RequestID,
		}

		events, err := s.backend.Trace(ctx, filter)
		if err != nil {
			return nil, nil, err
		}

		return nil, events, nil
	})
}
