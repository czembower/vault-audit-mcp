package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"vault-audit-mcp/internal/loki"
)

// LokiBackend implements Backend using Loki as the storage backend.
type LokiBackend struct {
	client *loki.Client
}

const queryChunkDuration = 10 * time.Minute
const maxPerQueryRangeLimit = 25

// NewLokiBackend creates a new Loki backend instance.
func NewLokiBackend(client *loki.Client) *LokiBackend {
	return &LokiBackend{client: client}
}

// normalizeNamespace ensures namespace paths have a trailing slash for consistency
// with how Vault formats namespaces in audit logs. This makes queries more user-friendly
// by accepting both "admin" and "admin/" as equivalent inputs.
func normalizeNamespace(ns string) string {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return ""
	}
	if !strings.HasSuffix(ns, "/") {
		return ns + "/"
	}
	return ns
}

// Search returns audit events matching the provided filter.
func (b *LokiBackend) Search(ctx context.Context, filter *SearchFilter) ([]Event, error) {
	// Validate resource limits
	duration := filter.End.Sub(filter.Start)
	if duration > time.Duration(MaxQueryDays)*24*time.Hour {
		return nil, fmt.Errorf("query time range exceeds maximum of %d days", MaxQueryDays)
	}

	debug := strings.EqualFold(os.Getenv("AUDIT_DEBUG_LOG"), "1") ||
		strings.EqualFold(os.Getenv("AUDIT_DEBUG_LOG"), "true")

	// Normalize limit
	if filter.Limit <= 0 || filter.Limit > MaxQueryLimit {
		filter.Limit = DefaultLimit
	}
	limit := filter.Limit

	// Build label selector - use labels for exact filtering (much faster than content search)
	sel := loki.Selector{Labels: map[string]string{
		LabelService: ValueServiceVault,
		LabelKind:    ValueKindAudit,
	}}
	if filter.Namespace != "" {
		sel.Labels[LabelNamespace] = normalizeNamespace(filter.Namespace)
	}
	// Use label filters for better performance, except for special cases
	if filter.Status != "" {
		sel.Labels[LabelStatus] = filter.Status
	}
	if filter.MountType != "" {
		sel.Labels[LabelMountType] = filter.MountType
	}
	if filter.MountClass != "" {
		sel.Labels[LabelMountClass] = filter.MountClass
	}
	// Add operation label filter for normal operations
	// Special cases (login, write/update aliasing) handled in buildLogQLExpression
	opLower := strings.ToLower(strings.TrimSpace(filter.Operation))
	if filter.Operation != "" && opLower != "login" && opLower != "write" && opLower != "update" {
		sel.Labels[LabelOperation] = filter.Operation
	}

	// Add entity_id label filter if specified
	if filter.EntityID != "" {
		sel.Labels[LabelEntityID] = filter.EntityID
	}

	queryExpr := buildLogQLExpression(sel.String(), filter.Operation, "", "", filter.Policy)
	if debug {
		log.Printf("[audit-debug] search query=%s start=%s end=%s limit=%d", queryExpr, filter.Start.Format(time.RFC3339Nano), filter.End.Format(time.RFC3339Nano), filter.Limit)
	}

	matcher := newSearchFilterMatcher(filter, limit)
	events := make([]Event, 0, limit)
	logged := 0
	for _, w := range splitTimeRangeReverse(filter.Start, filter.End, queryChunkDuration) {
		remaining := limit - len(events)
		if remaining <= 0 {
			break
		}

		perCallLimit := remaining
		if perCallLimit > maxPerQueryRangeLimit {
			perCallLimit = maxPerQueryRangeLimit
		}

		var resp *loki.QueryRangeResponse
		for {
			var err error
			resp, err = b.client.QueryRange(ctx, queryExpr, w.Start, w.End, perCallLimit)
			if err == nil {
				break
			}
			if isResponseTooLargeErr(err) && perCallLimit > 1 {
				perCallLimit = perCallLimit / 2
				if perCallLimit < 1 {
					perCallLimit = 1
				}
				continue
			}
			return nil, fmt.Errorf("loki search query failed: %w", err)
		}

		for _, r := range resp.Data.Result {
			for _, v := range r.Values {
				if len(v) != 2 {
					continue
				}

				tsStr, ok := v[0].(string)
				if !ok {
					log.Printf("failed to assert timestamp as string")
					continue
				}
				t, terr := parseUnixNanoString(tsStr)
				if terr != nil {
					log.Printf("failed to parse timestamp: %v", terr)
					continue
				}

				logStr, ok := v[1].(string)
				if !ok {
					log.Printf("failed to assert log as string")
					continue
				}
				parsed := map[string]any{}
				if err := json.Unmarshal([]byte(logStr), &parsed); err != nil {
					log.Printf("failed to unmarshal audit log: %v", err)
					if debug && logged < 3 {
						log.Printf("[audit-debug] raw_line=%q", truncateDebugLine(logStr))
						logged++
					}
					continue
				}

				// Vector wraps the audit log under the 'audit' key
				// Extract it so we have the standard Vault audit structure
				auditData := parsed
				if auditNested, ok := parsed["audit"].(map[string]any); ok {
					auditData = auditNested
				}

				if debug && logged < 3 {
					reqBlock, _ := auditData["request"].(map[string]any)
					reqPath, _ := reqBlock["path"].(string)
					reqOp, _ := reqBlock["operation"].(string)
					reqMountType, _ := reqBlock["mount_type"].(string)
					reqMountClass, _ := reqBlock["mount_class"].(string)
					log.Printf("[audit-debug] request path=%q op=%q mount_type=%q mount_class=%q", reqPath, reqOp, reqMountType, reqMountClass)
					logged++
				}

				Redact(auditData)

				ev := Event{
					Time:   t,
					Raw:    auditData,
					Stream: r.Stream,
				}
				populateFromAudit(&ev, auditData)

				if matcher.matches(ev) {
					events = append(events, ev)
					if len(events) >= limit {
						return events, nil
					}
				}
			}
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

	// Normalize namespace to ensure trailing slash for consistency with Vault's format
	filter.Namespace = normalizeNamespace(filter.Namespace)

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

	if by == LabelMountClass {
		events, err := b.Search(ctx, &SearchFilter{
			Start:      filter.Start,
			End:        filter.End,
			Limit:      MaxQueryLimit,
			Namespace:  filter.Namespace,
			Operation:  filter.Operation,
			MountType:  filter.MountType,
			MountClass: filter.MountClass,
			Status:     filter.Status,
		})
		if err != nil {
			return nil, err
		}

		counts := make(map[string]int)
		for _, ev := range events {
			key := ev.MountClass
			if key == "" {
				key = "(none)"
			}
			counts[key]++
		}

		buckets := make([]Bucket, 0, len(counts))
		for k, v := range counts {
			buckets = append(buckets, Bucket{Key: k, Value: float64(v)})
		}
		return buckets, nil
	}

	// Build label selector - use labels for exact filtering (much faster than content search)
	sel := loki.Selector{Labels: map[string]string{
		LabelService: ValueServiceVault,
		LabelKind:    ValueKindAudit,
	}}
	if filter.Namespace != "" {
		sel.Labels[LabelNamespace] = normalizeNamespace(filter.Namespace)
	}
	// Use label filters for better performance
	if filter.Status != "" {
		sel.Labels[LabelStatus] = filter.Status
	}
	if filter.MountType != "" {
		sel.Labels[LabelMountType] = filter.MountType
	}
	if filter.MountClass != "" {
		sel.Labels[LabelMountClass] = filter.MountClass
	}
	// Add operation label filter for normal operations
	opLower := strings.ToLower(strings.TrimSpace(filter.Operation))
	if filter.Operation != "" && opLower != "login" && opLower != "write" && opLower != "update" {
		sel.Labels[LabelOperation] = filter.Operation
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
	queryExpr := buildLogQLExpression(sel.String(), filter.Operation, "", "", "")
	query := fmt.Sprintf(`sum by (%s) (count_over_time((%s)[%dm]))`, by, queryExpr, int(window.Minutes()))
	if strings.EqualFold(os.Getenv("AUDIT_DEBUG_LOG"), "1") ||
		strings.EqualFold(os.Getenv("AUDIT_DEBUG_LOG"), "true") {
		log.Printf("[audit-debug] aggregate query=%s start=%s end=%s", query, filter.Start.Format(time.RFC3339Nano), filter.End.Format(time.RFC3339Nano))
	}

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

func buildLogQLExpression(base, operation, mountType, mountClass, policy string) string {
	// Most filtering now done via labels for performance.
	// This function only handles special cases that can't be expressed as simple label filters:
	// - "login" searches for auth paths (not a real operation value)
	// - "write"/"update" aliasing (content filter since labels can't express OR logic)
	// - "policy" searches within comma-separated policy labels (uses regex to match)
	expr := base
	trimmedOp := strings.TrimSpace(operation)
	opLower := strings.ToLower(trimmedOp)
	if opLower == "login" {
		// Special case: search for login operations by path pattern
		expr = addSubstringFilter(expr, "auth/")
		expr = addSubstringFilter(expr, "/login")
	} else if opLower == "write" || opLower == "update" {
		// Special case: write and update are aliases in Vault
		// Use regex content filter since we can't do OR logic with labels
		expr = addRegexFilter(expr, `"operation":"(write|update)"`)
	}

	// Policy filtering: search for policy name in comma-separated label
	// Matches: "policyname", "policyname,other", "other,policyname", "other,policyname,another"
	if policy != "" {
		// Use regex to match policy in either vault_policies or vault_token_policies labels
		// Pattern: (^|,)policyname(,|$) to match exact policy name in comma-separated list
		escapedPolicy := strings.ReplaceAll(policy, ".", "\\.")
		policyPattern := fmt.Sprintf(`(^|,)%s(,|$)`, escapedPolicy)
		expr = fmt.Sprintf(`(%s | label_format vault_policies_and_token=vault_policies+","+vault_token_policies | vault_policies_and_token =~ %q)`,
			expr, policyPattern)
	}

	// mountType and mountClass are now handled via labels in the caller
	// Only kept here for backwards compatibility if called with them
	if mountType != "" {
		expr = addJSONFieldFilter(expr, "mount_type", mountType)
	}
	if mountClass != "" {
		expr = addJSONFieldFilter(expr, "mount_class", mountClass)
	}
	return expr
}

func addJSONFieldFilter(expr, field, value string) string {
	return fmt.Sprintf("(%s |= %q)", expr, fmt.Sprintf(`"%s":"%s"`, field, value))
}

func addSubstringFilter(expr, value string) string {
	return fmt.Sprintf("(%s |= %q)", expr, value)
}

func addRegexFilter(expr, value string) string {
	return fmt.Sprintf("(%s |~ %q)", expr, value)
}

func applySearchFilters(events []Event, filter *SearchFilter) []Event {
	if filter == nil {
		return events
	}

	limit := filter.Limit
	if limit <= 0 || limit > MaxQueryLimit {
		limit = DefaultLimit
	}

	matcher := newSearchFilterMatcher(filter, limit)
	if matcher.isNoop() {
		return events
	}

	filtered := make([]Event, 0, len(events))
	for _, ev := range events {
		if matcher.matches(ev) {
			filtered = append(filtered, ev)
			if len(filtered) >= limit {
				break
			}
		}
	}

	return filtered
}

type searchFilterMatcher struct {
	namespace  string
	operation  string
	mountType  string
	mountClass string
	status     string
	policy     string
	entityID   string
	loginQuery bool
}

func newSearchFilterMatcher(filter *SearchFilter, _ int) searchFilterMatcher {
	if filter == nil {
		return searchFilterMatcher{}
	}
	operation := strings.TrimSpace(filter.Operation)
	return searchFilterMatcher{
		namespace:  normalizeNamespace(filter.Namespace),
		operation:  operation,
		mountType:  strings.TrimSpace(filter.MountType),
		mountClass: strings.TrimSpace(filter.MountClass),
		status:     strings.TrimSpace(filter.Status),
		policy:     strings.TrimSpace(filter.Policy),
		entityID:   strings.TrimSpace(filter.EntityID),
		loginQuery: strings.EqualFold(operation, "login"),
	}
}

func (m searchFilterMatcher) isNoop() bool {
	return m.namespace == "" && m.operation == "" && m.mountType == "" && m.mountClass == "" && m.status == "" && m.policy == "" && m.entityID == ""
}

func (m searchFilterMatcher) matches(ev Event) bool {
	if m.namespace != "" && !strings.EqualFold(ev.Namespace, m.namespace) {
		return false
	}
	if m.loginQuery {
		if !strings.Contains(strings.ToLower(ev.Path), "/login") {
			return false
		}
	} else if m.operation != "" && !operationMatches(ev.Operation, m.operation) {
		return false
	}
	if m.mountType != "" && !strings.EqualFold(ev.MountType, m.mountType) {
		return false
	}
	if m.mountClass != "" && !strings.EqualFold(ev.MountClass, m.mountClass) {
		return false
	}
	if m.status != "" && !strings.EqualFold(ev.Status, m.status) {
		return false
	}
	if m.policy != "" && !containsPolicy(ev.Policies, m.policy) && !containsPolicy(ev.TokenPolicies, m.policy) {
		return false
	}
	if m.entityID != "" && !strings.EqualFold(ev.EntityID, m.entityID) {
		return false
	}
	return true
}

// containsPolicy checks if a policy name exists in a slice of policies (case-insensitive)
func containsPolicy(policies []string, policy string) bool {
	policyLower := strings.ToLower(policy)
	for _, p := range policies {
		if strings.ToLower(p) == policyLower {
			return true
		}
	}
	return false
}

func operationMatches(eventOp, filterOp string) bool {
	if strings.EqualFold(eventOp, filterOp) {
		return true
	}
	filterLower := strings.ToLower(strings.TrimSpace(filterOp))
	eventLower := strings.ToLower(strings.TrimSpace(eventOp))
	if filterLower == "write" && eventLower == "update" {
		return true
	}
	if filterLower == "update" && eventLower == "write" {
		return true
	}
	return false
}

func truncateDebugLine(line string) string {
	const maxLen = 500
	if len(line) > maxLen {
		return line[:maxLen] + "..."
	}
	return line
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

	events := make([]Event, 0, filter.Limit)
	for _, w := range splitTimeRangeReverse(filter.Start, filter.End, queryChunkDuration) {
		remaining := filter.Limit - len(events)
		if remaining <= 0 {
			break
		}

		perCallLimit := remaining
		if perCallLimit > maxPerQueryRangeLimit {
			perCallLimit = maxPerQueryRangeLimit
		}

		var resp *loki.QueryRangeResponse
		for {
			var err error
			resp, err = b.client.QueryRange(ctx, query, w.Start, w.End, perCallLimit)
			if err == nil {
				break
			}
			if isResponseTooLargeErr(err) && perCallLimit > 1 {
				perCallLimit = perCallLimit / 2
				if perCallLimit < 1 {
					perCallLimit = 1
				}
				continue
			}
			return nil, fmt.Errorf("loki trace query failed: %w", err)
		}

		for _, r := range resp.Data.Result {
			for _, v := range r.Values {
				if len(v) != 2 {
					continue
				}

				tsStr, ok := v[0].(string)
				if !ok {
					log.Printf("failed to assert timestamp as string")
					continue
				}
				t, terr := parseUnixNanoString(tsStr)
				if terr != nil {
					log.Printf("failed to parse timestamp: %v", terr)
					continue
				}

				logStr, ok := v[1].(string)
				if !ok {
					log.Printf("failed to assert log as string")
					continue
				}
				parsed := map[string]any{}
				if err := json.Unmarshal([]byte(logStr), &parsed); err != nil {
					log.Printf("failed to unmarshal audit log: %v", err)
					continue
				}

				// Vector wraps the audit log under the 'audit' key
				// Extract it so we have the standard Vault audit structure
				auditData := parsed
				if auditNested, ok := parsed["audit"].(map[string]any); ok {
					auditData = auditNested
				}

				Redact(auditData)

				ev := Event{
					Time:   t,
					Raw:    auditData,
					Stream: r.Stream,
				}
				populateFromAudit(&ev, auditData)
				events = append(events, ev)
				if len(events) >= filter.Limit {
					return events, nil
				}
			}
		}
	}

	return events, nil
}

type timeWindow struct {
	Start time.Time
	End   time.Time
}

// splitTimeRangeReverse splits [start,end] into fixed windows from newest to oldest.
func splitTimeRangeReverse(start, end time.Time, chunk time.Duration) []timeWindow {
	if !end.After(start) {
		return []timeWindow{{Start: start, End: end}}
	}
	if chunk <= 0 {
		chunk = queryChunkDuration
	}
	if end.Sub(start) <= chunk {
		return []timeWindow{{Start: start, End: end}}
	}

	windows := make([]timeWindow, 0, int(end.Sub(start)/chunk)+1)
	cursor := end
	for cursor.After(start) {
		windowStart := cursor.Add(-chunk)
		if windowStart.Before(start) {
			windowStart = start
		}
		windows = append(windows, timeWindow{Start: windowStart, End: cursor})
		cursor = windowStart
	}
	return windows
}

func isResponseTooLargeErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "resourceexhausted") ||
		strings.Contains(msg, "received message larger than max") ||
		strings.Contains(msg, "message larger than max")
}
