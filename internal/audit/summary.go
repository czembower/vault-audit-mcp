package audit

import (
	"fmt"
	"sort"
)

// SearchSummary provides a condensed response for search queries,
// focusing on patterns and key findings rather than raw events.
type SearchSummary struct {
	// Total count of matching events
	TotalEvents int `json:"total_events"`

	// Time range queried
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`

	// Key statistics
	Statistics map[string]interface{} `json:"statistics"`

	// Top occurrences of key dimensions
	TopNamespaces   []NamespaceCount  `json:"top_namespaces,omitempty"`
	TopOperations   []OperationCount  `json:"top_operations,omitempty"`
	TopMountTypes   []MountTypeCount  `json:"top_mount_types,omitempty"`
	TopMountClasses []MountClassCount `json:"top_mount_classes,omitempty"`
	TopPolicies     []PolicyCount     `json:"top_policies,omitempty"`
	SuccessRate     float64           `json:"success_rate"`

	// Security analysis
	CriticalEvents int `json:"critical_events"`  // System config, audit config, policy changes
	HighRiskEvents int `json:"high_risk_events"` // Auth config, failed operations, etc.

	// Event categorization breakdown
	EventCategories map[EventCategory]int `json:"event_categories"`

	// Identity/Actor information - WHO performed the actions
	TopActors []ActorActivity `json:"top_actors,omitempty"`

	// Key insights from semantic analysis
	KeyInsights []string `json:"key_insights,omitempty"`

	// Sample of actual events for context (limited)
	SampleEvents []Event `json:"sample_events"`

	// Flag indicating if results are complete or summarized
	Summarized bool `json:"summarized"`
}

// ActorActivity represents who (identity) performed actions and what they did
type ActorActivity struct {
	DisplayName string   `json:"display_name"`          // User/service name
	EntityID    string   `json:"entity_id,omitempty"`   // Vault entity ID
	RemoteAddr  string   `json:"remote_addr,omitempty"` // IP address
	EventCount  int      `json:"event_count"`           // How many events from this actor
	Operations  []string `json:"operations,omitempty"`  // What operations they performed
	Namespaces  []string `json:"namespaces,omitempty"`  // Which namespaces they accessed
	Policies    []string `json:"policies,omitempty"`    // Unique policies used
}

type NamespaceCount struct {
	Namespace string `json:"namespace"`
	Count     int    `json:"count"`
}

type OperationCount struct {
	Operation string `json:"operation"`
	Count     int    `json:"count"`
}

type MountTypeCount struct {
	MountType string `json:"mount_type"`
	Count     int    `json:"count"`
}

type MountClassCount struct {
	MountClass string `json:"mount_class"`
	Count      int    `json:"count"`
}

type PolicyCount struct {
	Policy string `json:"policy"`
	Count  int    `json:"count"`
}

// SummarizeSearch creates a condensed summary from raw events.
func SummarizeSearch(events []Event, totalMatched int, startTime, endTime string) *SearchSummary {
	summary := &SearchSummary{
		TotalEvents:     totalMatched,
		StartTime:       startTime,
		EndTime:         endTime,
		Statistics:      make(map[string]interface{}),
		EventCategories: make(map[EventCategory]int),
		KeyInsights:     make([]string, 0),
	}

	// Count occurrences
	namespaceCounts := make(map[string]int)
	operationCounts := make(map[string]int)
	mountTypeCounts := make(map[string]int)
	mountClassCounts := make(map[string]int)
	policyCounts := make(map[string]int)
	successCount := 0
	errorCount := 0
	seenInsights := make(map[string]bool)

	// Track actors (display_name + remote_addr) and their activities
	actorActivity := make(map[string]*ActorActivity) // key: "displayname|remoteaddr|entityid"

	for _, event := range events {
		if event.Namespace != "" {
			namespaceCounts[event.Namespace]++
		}
		if event.Operation != "" {
			operationCounts[event.Operation]++
		}
		if event.MountType != "" {
			mountTypeCounts[event.MountType]++
		}
		if event.MountClass != "" {
			mountClassCounts[event.MountClass]++
		}
		// Count all policies (both policies and token_policies)
		for _, p := range event.Policies {
			if p != "" {
				policyCounts[p]++
			}
		}
		for _, p := range event.TokenPolicies {
			if p != "" {
				policyCounts[p]++
			}
		}
		if event.Status == "ok" {
			successCount++
		} else if event.Status == "error" {
			errorCount++
		}

		// Analyze event for categorization and severity
		analysis := AnalyzeEvent(&event)
		summary.EventCategories[analysis.Category]++

		switch analysis.Severity {
		case SeverityCritical:
			summary.CriticalEvents++
		case SeverityHigh:
			summary.HighRiskEvents++
		}

		// Collect unique insights
		if analysis.KeyInsight != "" && !seenInsights[analysis.KeyInsight] {
			summary.KeyInsights = append(summary.KeyInsights, analysis.KeyInsight)
			seenInsights[analysis.KeyInsight] = true
		}

		// Track actor activity
		if event.Display != "" || event.RemoteAddr != "" || event.EntityID != "" {
			actorKey := event.Display + "|" + event.RemoteAddr + "|" + event.EntityID
			actor, exists := actorActivity[actorKey]
			if !exists {
				actor = &ActorActivity{
					DisplayName: event.Display,
					EntityID:    event.EntityID,
					RemoteAddr:  event.RemoteAddr,
					Operations:  make([]string, 0),
					Namespaces:  make([]string, 0),
					Policies:    make([]string, 0),
				}
				actorActivity[actorKey] = actor
			}
			actor.EventCount++

			// Track unique operations
			if event.Operation != "" && !contains(actor.Operations, event.Operation) {
				actor.Operations = append(actor.Operations, event.Operation)
			}

			// Track unique namespaces
			if event.Namespace != "" && !contains(actor.Namespaces, event.Namespace) {
				actor.Namespaces = append(actor.Namespaces, event.Namespace)
			}

			// Track unique policies
			for _, p := range event.Policies {
				if p != "" && !contains(actor.Policies, p) {
					actor.Policies = append(actor.Policies, p)
				}
			}
			for _, p := range event.TokenPolicies {
				if p != "" && !contains(actor.Policies, p) {
					actor.Policies = append(actor.Policies, p)
				}
			}
		}
	}

	// Convert actors to sorted slice (top 10)
	summary.TopActors = topActors(actorActivity, 10)

	// Convert to sorted slices (top 5 each)
	summary.TopNamespaces = topNamespaces(namespaceCounts, 5)
	summary.TopOperations = topOperations(operationCounts, 5)
	summary.TopMountTypes = topMountTypes(mountTypeCounts, 5)
	summary.TopMountClasses = topMountClasses(mountClassCounts, 5)
	summary.TopPolicies = topPolicies(policyCounts, 10)

	// Calculate success rate
	totalWithStatus := successCount + errorCount
	if totalWithStatus > 0 {
		summary.SuccessRate = float64(successCount) / float64(totalWithStatus)
	}

	// Include first few events as samples (without Raw data to reduce size)
	summary.SampleEvents = stripRawData(events)
	if len(summary.SampleEvents) > 5 {
		summary.SampleEvents = summary.SampleEvents[:5]
	}

	// Mark as summarized if we're showing fewer events than matched
	summary.Summarized = len(events) < totalMatched

	summary.Statistics["total_success"] = successCount
	summary.Statistics["total_errors"] = errorCount
	summary.Statistics["critical_events"] = summary.CriticalEvents
	summary.Statistics["high_risk_events"] = summary.HighRiskEvents

	// Add summary insights
	if summary.CriticalEvents > 0 {
		summary.KeyInsights = append(summary.KeyInsights, fmt.Sprintf("%d critical events detected", summary.CriticalEvents))
	}
	if errorCount > 0 {
		summary.KeyInsights = append(summary.KeyInsights, fmt.Sprintf("%d failed operations", errorCount))
	}

	return summary
}

// TraceSummary provides a condensed response for trace queries.
type TraceSummary struct {
	RequestID    string   `json:"request_id"`
	TotalEvents  int      `json:"total_events"`
	StartTime    string   `json:"start_time"`
	EndTime      string   `json:"end_time"`
	Timeline     string   `json:"timeline"` // Human-readable timeline
	FirstEvent   *Event   `json:"first_event,omitempty"`
	LastEvent    *Event   `json:"last_event,omitempty"`
	Namespaces   []string `json:"namespaces"`
	Operations   []string `json:"operations"`
	Summarized   bool     `json:"summarized"`
	SampleEvents []Event  `json:"sample_events"`
}

// SummarizeTrace creates a condensed summary from trace results.
func SummarizeTrace(events []Event, requestID string, startTime, endTime string) *TraceSummary {
	summary := &TraceSummary{
		RequestID:   requestID,
		TotalEvents: len(events),
		StartTime:   startTime,
		EndTime:     endTime,
		Namespaces:  uniqueStrings(events, func(e Event) string { return e.Namespace }),
		Operations:  uniqueStrings(events, func(e Event) string { return e.Operation }),
	}

	if len(events) > 0 {
		summary.FirstEvent = &events[0]
		summary.LastEvent = &events[len(events)-1]
		summary.Timeline = fmt.Sprintf("Trace started at %v and ended at %v (%d events)",
			events[0].Time.Format("15:04:05"), events[len(events)-1].Time.Format("15:04:05"), len(events))
	}

	// Include sample events without Raw data
	strippedEvents := stripRawData(events)
	if len(strippedEvents) > 3 {
		summary.SampleEvents = strippedEvents[:3]
		summary.Summarized = true
	} else {
		summary.SampleEvents = strippedEvents
		summary.Summarized = false
	}

	return summary
}

// Helper functions

func topNamespaces(counts map[string]int, limit int) []NamespaceCount {
	var items []NamespaceCount
	for k, v := range counts {
		items = append(items, NamespaceCount{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func topOperations(counts map[string]int, limit int) []OperationCount {
	var items []OperationCount
	for k, v := range counts {
		items = append(items, OperationCount{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func topMountTypes(counts map[string]int, limit int) []MountTypeCount {
	var items []MountTypeCount
	for k, v := range counts {
		items = append(items, MountTypeCount{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func topMountClasses(counts map[string]int, limit int) []MountClassCount {
	var items []MountClassCount
	for k, v := range counts {
		items = append(items, MountClassCount{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func topPolicies(counts map[string]int, limit int) []PolicyCount {
	var items []PolicyCount
	for k, v := range counts {
		items = append(items, PolicyCount{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func stripRawData(events []Event) []Event {
	var result []Event
	for _, e := range events {
		e.Raw = nil // Remove raw JSON data to reduce size
		result = append(result, e)
	}
	return result
}

func uniqueStrings(events []Event, getter func(Event) string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, e := range events {
		s := getter(e)
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func topActors(actors map[string]*ActorActivity, limit int) []ActorActivity {
	var items []ActorActivity
	for _, actor := range actors {
		items = append(items, *actor)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].EventCount > items[j].EventCount })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
