package audit

import (
	"context"
	"testing"
)

// MockBackend is a test implementation of the Backend interface.
type MockBackend struct{}

func (m *MockBackend) Search(ctx context.Context, filter *SearchFilter) ([]Event, error) {
	return nil, nil
}

func (m *MockBackend) Aggregate(ctx context.Context, filter *AggregateFilter, by string) ([]Bucket, error) {
	return nil, nil
}

func (m *MockBackend) Trace(ctx context.Context, filter *TraceFilter) ([]Event, error) {
	return nil, nil
}

func TestNewService(t *testing.T) {
	backend := &MockBackend{}
	svc := NewService(backend)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
}

func TestNewServicePanicsOnNilBackend(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewService did not panic with nil backend")
		}
	}()
	NewService(nil)
}

func TestParseRangeDefaults(t *testing.T) {
	start, end, err := parseRange("", "")
	if err != nil {
		t.Fatalf("parseRange failed: %v", err)
	}
	if !start.Before(end) {
		t.Error("start should be before end")
	}
}

func TestParseRangeRejectsInvalidTimeFormat(t *testing.T) {
	_, _, err := parseRange("invalid", "")
	if err == nil {
		t.Fatal("parseRange should reject invalid time format")
	}
}

func TestParseRangeRejectsStartAfterEnd(t *testing.T) {
	start := "2025-02-01T11:00:00Z"
	end := "2025-02-01T10:00:00Z"
	_, _, err := parseRange(start, end)
	if err == nil {
		t.Fatal("parseRange should reject start time after end time")
	}
}

func TestRedact(t *testing.T) {
	data := map[string]any{
		"auth": map[string]any{
			"client_token": "s.token123",
			"display_name": "my-user",
		},
	}
	Redact(data)
	auth := data["auth"].(map[string]any)
	if auth["client_token"] != "[redacted]" {
		t.Error("auth.client_token should be redacted")
	}
	if auth["display_name"] != "my-user" {
		t.Error("auth.display_name should not be redacted")
	}
}
