package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"vault-audit-mcp/internal/loki"
)

// LokiBackend implements Backend using Loki as the storage backend.
type LokiBackend struct {
	client *loki.Client
}

// NewLokiBackend creates a new Loki backend instance.
func NewLokiBackend(client *loki.Client) *LokiBackend {
	return &LokiBackend{client: client}
}

// Search returns audit events matching the provided filter.
func (b *LokiBackend) Search(ctx context.Context, filter *SearchFilter) ([]Event, error) {
	// Validate resource limits
	duration := filter.End.Sub(filter.Start)
	if duration > time.Duration(MaxQueryDays)*24*time.Hour {
		return nil, fmt.Errorf("query time range exceeds maximum of %d days", MaxQueryDays)
	}

	// Normalize limit
	if filter.Limit <= 0 || filter.Limit > MaxQueryLimit {
		filter.Limit = DefaultLimit
	}

	// Build label selector
	sel := loki.Selector{Labels: map[string]string{
		LabelService: ValueServiceVault,
		LabelKind:    ValueKindAudit,
	}}
	if filter.Namespace != "" {
		sel.Labels[LabelNamespace] = filter.Namespace
	}
	if filter.Operation != "" {
		sel.Labels[LabelOperation] = filter.Operation
	}
	if filter.MountType != "" {
		sel.Labels[LabelMountType] = filter.MountType
	}
	if filter.Status != "" {
		sel.Labels[LabelStatus] = filter.Status
	}

	resp, err := b.client.QueryRange(ctx, sel.String(), filter.Start, filter.End, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("loki search query failed: %w", err)
	}

	events := make([]Event, 0, filter.Limit)
	for _, r := range resp.Data.Result {
		for _, v := range r.Values {
			if len(v) != 2 {
				continue
			}

			t, terr := parseUnixNanoString(v[0])
			if terr != nil {
				log.Printf("failed to parse timestamp: %v", terr)
				continue
			}

			parsed := map[string]any{}
			if err := json.Unmarshal([]byte(v[1]), &parsed); err != nil {
				log.Printf("failed to unmarshal audit log: %v", err)
				continue
			}

			Redact(parsed)

			ev := Event{
				Time:   t,
				Raw:    parsed,
				Stream: r.Stream,
			}
			populateFromAudit(&ev, parsed)
			events = append(events, ev)
		}
	}

	return events, nil
}

// Aggregate returns event counts grouped by the specified dimension.
func (b *LokiBackend) Aggregate(ctx context.Context, filter *AggregateFilter, by string) ([]Bucket, error) {
	// Validate resource limits
	duration := filter.End.Sub(filter.Start)
	if duration > time.Duration(MaxQueryDays)*24*time.Hour {
		return nil, fmt.Errorf("query time range exceeds maximum of %d days", MaxQueryDays)
	}

	// Validate 'by' parameter
	validDimensions := map[string]bool{
		LabelNamespace: true,
		LabelOperation: true,
		LabelMountType: true,
		LabelStatus:    true,
	}
	if !validDimensions[by] {
		return nil, fmt.Errorf("invalid aggregation dimension: %q", by)
	}

	// Build label selector
	sel := loki.Selector{Labels: map[string]string{
		LabelService: ValueServiceVault,
		LabelKind:    ValueKindAudit,
	}}
	if filter.Namespace != "" {
		sel.Labels[LabelNamespace] = filter.Namespace
	}
	if filter.Operation != "" {
		sel.Labels[LabelOperation] = filter.Operation
	}
	if filter.MountType != "" {
		sel.Labels[LabelMountType] = filter.MountType
	}
	if filter.Status != "" {
		sel.Labels[LabelStatus] = filter.Status
	}

	// Calculate aggregation window based on query duration (e.g., 1% of total duration, min 1m, max 1h)
	// Note: 'duration' already calculated above for validation
	window := duration / 100
	if window < time.Minute {
		window = time.Minute
	}
	if window > time.Hour {
		window = time.Hour
	}

	// Metric query: count_over_time by label over the calculated window
	query := fmt.Sprintf(`sum by (%s) (count_over_time(%s[%dm]))`, by, sel.String(), int(window.Minutes()))

	resp, err := b.client.QueryRange(ctx, query, filter.Start, filter.End, 0)
	if err != nil {
		return nil, fmt.Errorf("loki aggregate query failed: %w", err)
	}

	buckets := []Bucket{}
	for _, r := range resp.Data.Result {
		k := r.Stream[by]
		if k == "" {
			k = "(none)"
		}
		latest := latestValue(r.Values)
		buckets = append(buckets, Bucket{Key: k, Value: latest})
	}

	return buckets, nil
}

// Trace returns events for a specific request ID.
func (b *LokiBackend) Trace(ctx context.Context, filter *TraceFilter) ([]Event, error) {
	// Validate resource limits
	duration := filter.End.Sub(filter.Start)
	if duration > time.Duration(MaxQueryDays)*24*time.Hour {
		return nil, fmt.Errorf("query time range exceeds maximum of %d days", MaxQueryDays)
	}

	// Normalize limit
	if filter.Limit <= 0 || filter.Limit > MaxQueryLimit {
		filter.Limit = DefaultLimit
	}

	if filter.RequestID == "" {
		return nil, fmt.Errorf("request_id is required")
	}

	// Build label selector
	sel := loki.Selector{Labels: map[string]string{
		LabelService: ValueServiceVault,
		LabelKind:    ValueKindAudit,
	}}

	// Use content filter to find request ID in JSON payload
	query := fmt.Sprintf(`%s |= %q`, sel.String(), filter.RequestID)

	resp, err := b.client.QueryRange(ctx, query, filter.Start, filter.End, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("loki trace query failed: %w", err)
	}

	events := make([]Event, 0, filter.Limit)
	for _, r := range resp.Data.Result {
		for _, v := range r.Values {
			if len(v) != 2 {
				continue
			}

			t, terr := parseUnixNanoString(v[0])
			if terr != nil {
				log.Printf("failed to parse timestamp: %v", terr)
				continue
			}

			parsed := map[string]any{}
			if err := json.Unmarshal([]byte(v[1]), &parsed); err != nil {
				log.Printf("failed to unmarshal audit log: %v", err)
				continue
			}

			Redact(parsed)

			ev := Event{
				Time:   t,
				Raw:    parsed,
				Stream: r.Stream,
			}
			populateFromAudit(&ev, parsed)
			events = append(events, ev)
		}
	}

	return events, nil
}
