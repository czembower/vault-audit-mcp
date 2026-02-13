package audit

import (
	"fmt"
	"strconv"
	"time"
)

// Redact removes or masks sensitive fields from audit event data.
// It modifies the map in-place to remove secrets, tokens, and credentials.
func Redact(m map[string]any) {
	if m == nil {
		return
	}

	// Top-level sensitive fields
	sensitiveTopLevel := []string{"error", "errors"}
	for _, field := range sensitiveTopLevel {
		if val, ok := m[field]; ok && val != nil {
			m[field] = "[redacted]"
		}
	}

	// auth block contains sensitive tokens
	if auth, ok := m["auth"].(map[string]any); ok {
		authSensitive := []string{"client_token", "accessor", "secret_id", "metadata"}
		for _, field := range authSensitive {
			if auth[field] != nil {
				auth[field] = "[redacted]"
			}
		}
	}

	// response block may contain sensitive data
	if resp, ok := m["response"].(map[string]any); ok {
		// Redact auth within response
		if auth, ok := resp["auth"].(map[string]any); ok {
			authSensitive := []string{"client_token", "accessor", "secret_id"}
			for _, field := range authSensitive {
				if auth[field] != nil {
					auth[field] = "[redacted]"
				}
			}
		}
		// Redact secret data
		if secret, ok := resp["secret"].(map[string]any); ok {
			secretSensitive := []string{"data"}
			for _, field := range secretSensitive {
				if secret[field] != nil {
					secret[field] = "[redacted]"
				}
			}
		}
		// Redact wake-up keys and other sensitive response data
		respSensitive := []string{"data", "wrap_info"}
		for _, field := range respSensitive {
			if _, ok := resp[field]; ok {
				// For 'data', be selective rather than blanking everything
				// Some backends return structured data we want to preserve shape of
				if field == "wrap_info" {
					resp[field] = "[redacted]"
				}
			}
		}
	}

	// request block may contain sensitive path or body parameters
	if req, ok := m["request"].(map[string]any); ok {
		// Don't redact the path itself, but redact data if present
		if req["data"] != nil {
			req["data"] = "[redacted]"
		}
	}
}

func parseUnixNanoString(ns string) (time.Time, error) {
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	sec := n / 1_000_000_000
	nsec := n % 1_000_000_000
	return time.Unix(sec, nsec).UTC(), nil
}

func populateFromAudit(ev *Event, m map[string]any) {
	// type
	if v, ok := m["type"].(string); ok {
		ev.AuditType = v
	}

	// request.*
	req, _ := m["request"].(map[string]any)
	if req != nil {
		if v, ok := req["operation"].(string); ok {
			ev.Operation = v
		}
		if v, ok := req["path"].(string); ok {
			ev.Path = v
		}
		if v, ok := req["mount_type"].(string); ok {
			ev.MountType = v
		}
		if v, ok := req["mount_class"].(string); ok {
			ev.MountClass = v
		}
		if v, ok := req["id"].(string); ok {
			ev.RequestID = v
		}
		if v, ok := req["remote_address"].(string); ok {
			ev.RemoteAddr = v
		}
		if ns, ok := req["namespace"].(map[string]any); ok {
			if p, ok := ns["path"].(string); ok && p != "" {
				ev.Namespace = p
			}
		}
	}

	// response.* (fallbacks when request block is missing or empty)
	if resp, ok := m["response"].(map[string]any); ok {
		if ev.MountType == "" {
			if v, ok := resp["mount_type"].(string); ok {
				ev.MountType = v
			}
		}
		if ev.MountClass == "" {
			if v, ok := resp["mount_class"].(string); ok {
				ev.MountClass = v
			}
		}
		if ev.Display == "" {
			if auth, ok := resp["auth"].(map[string]any); ok {
				if v, ok := auth["display_name"].(string); ok {
					ev.Display = v
				}
			}
		}
	}

	// auth.display_name
	if auth, ok := m["auth"].(map[string]any); ok {
		if v, ok := auth["display_name"].(string); ok {
			ev.Display = v
		}
		// Extract policy information
		if policies, ok := auth["policies"].([]interface{}); ok {
			ev.Policies = make([]string, 0, len(policies))
			for _, p := range policies {
				if pStr, ok := p.(string); ok {
					ev.Policies = append(ev.Policies, pStr)
				}
			}
		}
		if tokenPolicies, ok := auth["token_policies"].([]interface{}); ok {
			ev.TokenPolicies = make([]string, 0, len(tokenPolicies))
			for _, p := range tokenPolicies {
				if pStr, ok := p.(string); ok {
					ev.TokenPolicies = append(ev.TokenPolicies, pStr)
				}
			}
		}
		if entityID, ok := auth["entity_id"].(string); ok {
			ev.EntityID = entityID
		}
	}

	// top-level fallbacks for flattened audit logs
	if ev.Path == "" {
		if v, ok := m["path"].(string); ok {
			ev.Path = v
		}
	}
	if ev.Operation == "" {
		if v, ok := m["operation"].(string); ok {
			ev.Operation = v
		}
	}
	if ev.MountType == "" {
		if v, ok := m["mount_type"].(string); ok {
			ev.MountType = v
		}
	}
	if ev.MountClass == "" {
		if v, ok := m["mount_class"].(string); ok {
			ev.MountClass = v
		}
	}

	// status (best-effort)
	ev.Status = "ok"
	if _, ok := m["error"]; ok {
		// error may be null; treat any non-empty as error
		if m["error"] != nil && fmt.Sprintf("%v", m["error"]) != "" {
			ev.Status = "error"
		}
	}
}

func latestValue(values [][]interface{}) float64 {
	// values: [[ts, "number/metric"], ...] - second element can be string or numeric from Loki
	if len(values) == 0 {
		return 0
	}
	last := values[len(values)-1]
	if len(last) != 2 {
		return 0
	}

	// Handle both string (from log queries) and numeric (from metric queries) values
	var strVal string
	switch v := last[1].(type) {
	case string:
		strVal = v
	case float64:
		strVal = strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return 0
	}

	f, err := strconv.ParseFloat(strVal, 64)
	if err != nil {
		return 0
	}
	return f
}
