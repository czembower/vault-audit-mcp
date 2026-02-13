package audit

import (
	"strings"
)

// inferMountTypeFromPath infers the actual mount type from the API path
// when the mount_type field is missing or incorrect.
// This handles cases where Vault's audit log doesn't populate mount_type properly.
func inferMountTypeFromPath(path string) string {
	pathLower := strings.ToLower(path)

	// Auth methods - path like /auth/{method}/login or auth/{method}/login
	if strings.HasPrefix(pathLower, "/auth/") || strings.HasPrefix(pathLower, "auth/") {
		trimmed := strings.TrimPrefix(pathLower, "/auth/")
		trimmed = strings.TrimPrefix(trimmed, "auth/")
		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0] // "oidc", "ldap", "approle", "userpass", etc.
		}
		return "auth"
	}

	// Secret engines - kv, kv-v2, etc.
	if strings.Contains(pathLower, "/data/") || strings.Contains(pathLower, "/secret/") {
		return "kv"
	}

	// PKI operations
	if strings.Contains(pathLower, "/pki/") {
		return "pki"
	}

	// Transit
	if strings.Contains(pathLower, "/transit/") {
		return "transit"
	}

	// Database
	if strings.Contains(pathLower, "/database/") {
		return "database"
	}

	// SSH
	if strings.Contains(pathLower, "/ssh/") {
		return "ssh"
	}

	// Generic secret engine pattern
	if strings.Contains(pathLower, "/metadata/") || strings.Contains(pathLower, "/versions/") {
		return "kv"
	}

	// System operations
	if strings.HasPrefix(pathLower, "/sys/") {
		return "ns_system"
	}

	// Identity/entity
	if strings.Contains(pathLower, "/identity/") || strings.Contains(pathLower, "/entity/") {
		return "identity"
	}

	// Token operations
	if strings.Contains(pathLower, "/auth/token") {
		return "token"
	}

	return ""
}

// EventCategory represents a semantic category for an audit event
type EventCategory string

const (
	CategoryAuthConfig   EventCategory = "authentication_config"  // Auth method configuration
	CategoryAuthAttempt  EventCategory = "authentication_attempt" // Login/authentication
	CategorySecretAccess EventCategory = "secret_access"          // Reading/writing secrets
	CategorySecretConfig EventCategory = "secret_config"          // Secret engine configuration
	CategoryPKI          EventCategory = "pki_operations"         // PKI certificate operations
	CategoryPolicyConfig EventCategory = "policy_configuration"   // Policy management
	CategoryRoleConfig   EventCategory = "role_configuration"     // Role/AppRole management
	CategoryAuditConfig  EventCategory = "audit_configuration"    // Audit system changes
	CategorySystemConfig EventCategory = "system_configuration"   // Core system configuration
	CategoryTokenMgmt    EventCategory = "token_management"       // Token creation/revocation
	CategoryEntityMgmt   EventCategory = "identity_management"    // Identity/entity operations
	CategoryMountMgmt    EventCategory = "mount_management"       // Mount enable/disable
	CategoryOther        EventCategory = "other"                  // Uncategorized
)

// EventSeverity represents the security significance of an event
type EventSeverity string

const (
	SeverityCritical EventSeverity = "critical" // System config, audit config, policy changes
	SeverityHigh     EventSeverity = "high"     // Auth config, role config, failed auth
	SeverityMedium   EventSeverity = "medium"   // Secret config, PKI operations
	SeverityLow      EventSeverity = "low"      // Normal secret reads
	SeverityInfo     EventSeverity = "info"     // Other operations
)

// EventAnalysis contains deeper semantic understanding of an event
type EventAnalysis struct {
	Category      EventCategory `json:"category"`
	Severity      EventSeverity `json:"severity"`
	Description   string        `json:"description"`
	KeyInsight    string        `json:"key_insight,omitempty"`
	IsAnomaly     bool          `json:"is_anomaly,omitempty"`
	AnomalyReason string        `json:"anomaly_reason,omitempty"`
}

// AnalyzeEvent performs intelligent semantic analysis of an audit event
func AnalyzeEvent(event *Event) *EventAnalysis {
	analysis := &EventAnalysis{
		Category: CategoryOther,
		Severity: SeverityInfo,
	}

	// Infer mount_type from path if missing or empty
	// This handles cases where Vault's audit log doesn't populate mount_type
	if event.MountType == "" {
		inferredType := inferMountTypeFromPath(event.Path)
		if inferredType != "" {
			event.MountType = inferredType
		}
	}

	// System namespace events are always critical
	if strings.HasPrefix(event.Path, "ns_system/") || strings.HasPrefix(event.Path, "system/") {
		analysis.Severity = SeverityCritical
		analysis.IsAnomaly = true
		analysis.AnomalyReason = "System namespace operations are critical"
	}

	// Failed operations are always significant
	if event.Status == "error" {
		if analysis.Severity == SeverityInfo {
			analysis.Severity = SeverityHigh
		}
		analysis.KeyInsight = "Operation failed"
	}

	path := strings.ToLower(event.Path)

	// Categorize based on path patterns
	switch {
	// Authentication
	case strings.Contains(path, "/auth/") || strings.Contains(path, "auth/") || strings.Contains(path, "/identity/oidc/"):
		if strings.Contains(path, "config") || strings.Contains(path, "method") {
			analysis.Category = CategoryAuthConfig
			if analysis.Severity != SeverityCritical {
				analysis.Severity = SeverityHigh
			}
		} else if strings.Contains(path, "login") || strings.Contains(path, "userpass") || strings.Contains(path, "ldap") {
			analysis.Category = CategoryAuthAttempt
			if event.Status == "error" {
				analysis.Severity = SeverityHigh
				analysis.KeyInsight = "Authentication failed"
			} else {
				analysis.Severity = SeverityMedium
			}
		}

	// Secrets
	case strings.Contains(path, "/secret/") || strings.Contains(path, "/kv/") || strings.Contains(path, "/data/"):
		if strings.Contains(path, "config") {
			analysis.Category = CategorySecretConfig
			analysis.Severity = SeverityMedium
		} else if event.Operation == "read" || event.Operation == "list" {
			analysis.Category = CategorySecretAccess
			analysis.Severity = SeverityLow
		} else if event.Operation == "write" || event.Operation == "delete" {
			analysis.Category = CategorySecretAccess
			analysis.Severity = SeverityMedium
			analysis.KeyInsight = "Secret data modified"
		} else {
			analysis.Category = CategorySecretAccess
		}

	// PKI
	case strings.Contains(path, "/pki/") || strings.Contains(path, "/cert"):
		analysis.Category = CategoryPKI
		if strings.Contains(path, "config") || strings.Contains(path, "issue/") || strings.Contains(path, "sign/") {
			analysis.Severity = SeverityMedium
		} else {
			analysis.Severity = SeverityLow
		}

	// Policy
	case strings.Contains(path, "/policy/") || strings.Contains(path, "/policies/"):
		analysis.Category = CategoryPolicyConfig
		analysis.Severity = SeverityCritical
		if event.Operation == "write" || event.Operation == "delete" {
			analysis.KeyInsight = "Policy modified"
		}

	// Roles and AppRoles
	case strings.Contains(path, "/approle/") || strings.Contains(path, "/role/"):
		analysis.Category = CategoryRoleConfig
		if event.Operation == "write" || event.Operation == "delete" {
			analysis.Severity = SeverityHigh
			analysis.KeyInsight = "Role configuration changed"
		} else {
			analysis.Severity = SeverityMedium
		}

	// Audit system
	case strings.Contains(path, "/audit"):
		analysis.Category = CategoryAuditConfig
		analysis.Severity = SeverityCritical
		if event.Operation == "write" || event.Operation == "delete" {
			analysis.KeyInsight = "Audit system modified"
		}

	// System configuration
	case strings.Contains(path, "/auth/enable") || strings.Contains(path, "/auth/disable") ||
		strings.Contains(path, "/sys/mounts") || strings.Contains(path, "/sys/config"):
		analysis.Category = CategorySystemConfig
		analysis.Severity = SeverityCritical

	// Token management
	case strings.Contains(path, "/auth/token") || strings.Contains(path, "/token/"):
		analysis.Category = CategoryTokenMgmt
		if event.Operation == "create" || event.Operation == "renew" {
			analysis.Severity = SeverityMedium
		} else if event.Operation == "revoke" {
			analysis.Severity = SeverityMedium
		} else {
			analysis.Severity = SeverityLow
		}

	// Identity/Entity management
	case strings.Contains(path, "/identity/") || strings.Contains(path, "/entity/"):
		analysis.Category = CategoryEntityMgmt
		if strings.Contains(path, "config") {
			analysis.Severity = SeverityHigh
		} else {
			analysis.Severity = SeverityMedium
		}

	// Mount management
	case strings.Contains(path, "/sys/mounts") && (event.Operation == "write" || event.Operation == "delete"):
		analysis.Category = CategoryMountMgmt
		analysis.Severity = SeverityHigh
	}

	// Set description based on category and operation
	analysis.Description = describeEvent(event, analysis.Category)

	return analysis
}

// describeEvent generates a human-readable description of an event
func describeEvent(event *Event, category EventCategory) string {
	op := event.Operation
	mount := event.MountType
	if mount == "" {
		mount = "unknown"
	}

	switch category {
	case CategoryAuthConfig:
		return "Authentication configuration change (mount: " + mount + ")"
	case CategoryAuthAttempt:
		status := "attempted"
		if event.Status == "ok" {
			status = "successful"
		}
		return "User " + status + " authentication via " + mount
	case CategorySecretAccess:
		return "Secret " + op + " on path: " + truncatePath(event.Path)
	case CategorySecretConfig:
		return "Secret engine configuration change (mount: " + mount + ")"
	case CategoryPKI:
		return "PKI operation: " + op + " (mount: " + mount + ")"
	case CategoryPolicyConfig:
		return "Policy " + op + " operation"
	case CategoryRoleConfig:
		return "Role configuration " + op + " (mount: " + mount + ")"
	case CategoryAuditConfig:
		return "Audit system " + op + " operation"
	case CategorySystemConfig:
		return "System configuration " + op + " operation"
	case CategoryTokenMgmt:
		return "Token " + op + " operation"
	case CategoryEntityMgmt:
		return "Identity/entity " + op + " operation"
	case CategoryMountMgmt:
		return "Mount " + op + " operation (mount: " + mount + ")"
	default:
		return op + " on path: " + truncatePath(event.Path) + " (mount: " + mount + ")"
	}
}

func truncatePath(path string) string {
	if len(path) > 50 {
		return path[:50] + "..."
	}
	return path
}

// EventInsightSummary provides categorized insights for multiple events
type EventInsightSummary struct {
	TotalEvents     int                   `json:"total_events"`
	CriticalEvents  int                   `json:"critical_events"`
	HighRiskEvents  int                   `json:"high_risk_events"`
	AnomalousEvents int                   `json:"anomalous_events"`
	FailedOps       int                   `json:"failed_operations"`
	Categories      map[EventCategory]int `json:"categories"`
	Insights        []string              `json:"insights"`
}

// SummarizeWithAnalysis creates insights from event analysis
func SummarizeWithAnalysis(events []Event) *EventInsightSummary {
	insights := &EventInsightSummary{
		TotalEvents: len(events),
		Categories:  make(map[EventCategory]int),
		Insights:    make([]string, 0),
	}

	seenAnomalies := make(map[string]bool)
	systemOpsCount := 0

	for _, event := range events {
		analysis := AnalyzeEvent(&event)

		insights.Categories[analysis.Category]++

		switch analysis.Severity {
		case SeverityCritical:
			insights.CriticalEvents++
		case SeverityHigh:
			insights.HighRiskEvents++
		}

		if analysis.IsAnomaly {
			insights.AnomalousEvents++
			if !seenAnomalies[analysis.AnomalyReason] {
				insights.Insights = append(insights.Insights, analysis.AnomalyReason)
				seenAnomalies[analysis.AnomalyReason] = true
			}
		}

		if event.Status == "error" {
			insights.FailedOps++
		}

		if strings.HasPrefix(event.Path, "ns_system/") || strings.HasPrefix(event.Path, "system/") {
			systemOpsCount++
		}
	}

	// Add high-level insights
	if insights.CriticalEvents > 0 {
		insights.Insights = append(insights.Insights,
			"Contains system and policy-level changes")
	}
	if insights.FailedOps > 0 {
		insights.Insights = append(insights.Insights,
			"Contains "+string(rune(insights.FailedOps))+" failed operations")
	}
	if systemOpsCount > 0 {
		insights.Insights = append(insights.Insights,
			"Includes "+string(rune(systemOpsCount))+" system namespace operations")
	}

	return insights
}
