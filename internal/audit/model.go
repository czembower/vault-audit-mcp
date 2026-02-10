package audit

import (
	"context"
	"time"
)

// Label constants for Loki queries
const (
	LabelService   = "service"
	LabelKind      = "log_kind"
	LabelNamespace = "vault_namespace"
	LabelOperation = "vault_operation"
	LabelMountType = "vault_mount_type"
	LabelStatus    = "vault_status"

	// Default Vault audit stream names
	ValueServiceVault = "vault"
	ValueKindAudit    = "audit"

	// Resource limits
	MaxQueryLimit   = 500
	DefaultLimit    = 100
	MaxQueryDays    = 90
	DefaultQueryAge = 15 * time.Minute
)

// Backend defines the interface for audit log storage backends.
type Backend interface {
	// Search returns audit events matching the criteria.
	Search(ctx context.Context, filter *SearchFilter) ([]Event, error)
	// Aggregate returns event counts grouped by a specified dimension.
	Aggregate(ctx context.Context, filter *AggregateFilter, by string) ([]Bucket, error)
	// Trace returns events for a specific request ID.
	Trace(ctx context.Context, filter *TraceFilter) ([]Event, error)
}

type SearchFilter struct {
	Start     time.Time
	End       time.Time
	Limit     int
	Namespace string
	Operation string
	MountType string
	Status    string
}

type AggregateFilter struct {
	Start     time.Time
	End       time.Time
	Namespace string
	Operation string
	MountType string
	Status    string
}

type TraceFilter struct {
	Start     time.Time
	End       time.Time
	Limit     int
	RequestID string
}

type Bucket struct {
	Key   string  `json:"key"`
	Value float64 `json:"value"`
}

type Event struct {
	Time       time.Time `json:"time"`
	Namespace  string    `json:"namespace,omitempty"`
	Operation  string    `json:"operation,omitempty"`
	MountType  string    `json:"mount_type,omitempty"`
	Path       string    `json:"path,omitempty"`
	AuditType  string    `json:"audit_type,omitempty"` // request/response
	Status     string    `json:"status,omitempty"`     // ok/error (best-effort)
	RequestID  string    `json:"request_id,omitempty"`
	Display    string    `json:"display_name,omitempty"`
	RemoteAddr string    `json:"remote_address,omitempty"`

	// Raw is optional; the redacted JSON object.
	Raw map[string]any `json:"raw,omitempty"`

	// Labels from Loki stream, if helpful for debugging.
	Stream map[string]string `json:"stream,omitempty"`
}
