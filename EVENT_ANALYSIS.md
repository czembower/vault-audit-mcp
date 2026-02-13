# Event Analysis & Semantic Understanding

## Overview

vault-audit-mcp now performs **intelligent semantic analysis** of audit events beyond simple dimension counting. Instead of treating all events as generic log lines, the analyzer understands:

- **Event categories** - What type of operation occurred (authentication, secret access, system config, etc.)
- **Severity levels** - How critical or risky an event is
- **Contextual insights** - What an event means in the context of Vault operations
- **Anomaly detection** - Flagging system namespace operations and configuration changes

## Event Categories

The analyzer categorizes all events into one of these categories:

| Category | Examples | Typical Severity |
|----------|----------|-----------------|
| `authentication_config` | Auth method setup, OIDC configuration | 🔴 HIGH |
| `authentication_attempt` | User login, token requests | 🟠 MEDIUM-HIGH |
| `secret_access` | Reading/writing secrets | 🟡 LOW-MEDIUM |
| `secret_config` | Secret engine configuration | 🟠 MEDIUM |
| `pki_operations` | Certificate issuance, signing | 🟡 MEDIUM |
| `policy_configuration` | Policy create/update/delete | 🔴 CRITICAL |
| `role_configuration` | AppRole, JWT role management | 🔴 HIGH |
| `audit_configuration` | Audit log setup/changes | 🔴 CRITICAL |
| `system_configuration` | Mount management, core config | 🔴 CRITICAL |
| `token_management` | Token creation, renewal, revocation | 🟠 MEDIUM |
| `identity_management` | Entity/identity setup, config | 🟠 MEDIUM |
| `mount_management` | Mount enable/disable operations | 🔴 HIGH |
| `other` | Uncategorized operations | 🟢 INFO |

## Severity Levels

Each event is assigned a severity that reflects its security significance:

### 🔴 **CRITICAL** 
- System namespace operations (`ns_system/*`, `system/*`)
- Policy modifications (any operation on `/policy/`)
- Audit system changes (any operation on `/audit`)
- System configuration changes (mount management, core config)

### 🔴 **HIGH**
- Authentication configuration changes
- Failed authentication attempts
- Role configuration modifications
- Mount management operations

### 🟠 **MEDIUM**
- Secret engine configuration
- PKI operations
- Token management
- Entity/identity operations
- Trace request lookups

### 🟡 **LOW**
- Normal secret reads
- Secret listings
- Non-write key-value operations

### 🟢 **INFO**
- Anything else not categorized above
- Status checks, metadata reads

## Example: What Gets Flagged

### Before (Raw Count)
```
"mount_type": "ns_system",
"operation": "update",
"path": "/sys/config/audit",
"status": "ok"
```
Just another event in the logs.

### After (Analyzed)
```json
{
  "category": "audit_configuration",
  "severity": "critical",
  "description": "Audit system update operation",
  "key_insight": "Audit system modified",
  "is_anomaly": true,
  "anomaly_reason": "System namespace operations are critical"
}
```
Now the LLM knows this is a critical change that modified the audit system itself.

## Response Format

The `SearchSummary` response now includes these analysis fields:

```json
{
  "total_events": 5247,
  "statistics": {
    "total_success": 5100,
    "total_errors": 147,
    "critical_events": 12,
    "high_risk_events": 87
  },
  "critical_events": 12,          ← Count at top level
  "high_risk_events": 87,         ← Count at top level
  
  "event_categories": {           ← NEW: Category breakdown
    "secret_access": 3200,
    "audit_configuration": 12,
    "system_configuration": 15,
    "policy_configuration": 8,
    "authentication_attempt": 1200,
    "other": 812
  },
  
  "key_insights": [               ← NEW: Semantic insights
    "Secret data modified",
    "Authentication failed",
    "Policy modified",
    "Audit system modified",
    "System namespace operations are critical",
    "12 critical events detected",
    "147 failed operations"
  ],
  
  "top_namespaces": [...],
  "top_operations": [...],
  "top_mount_types": [...],
  "success_rate": 0.972,
  "sample_events": [...],
  "summarized": true
}
```

## How the Analyzer Works

### Path-Based Classification

The analyzer looks at the audit event's `path` field and applies pattern matching:

```go
// Simplified example
switch {
case strings.Contains(path, "/auth/"):
    // Authentication-related
    
case strings.Contains(path, "/secret/") || strings.Contains(path, "/kv/"):
    // Secret operations
    
case strings.Contains(path, "/policy/"):
    // Policy operations → CRITICAL
    
case strings.HasPrefix(path, "ns_system/"):
    // System namespace → CRITICAL by default
}
```

### Severity Assignment

```
Start with base severity from category
  ↓
Check if operation is "write" or "delete" → increase severity
  ↓
Check if status is "error" → increase severity
  ↓
Check if path contains "system/" or "ns_system/" → increase to CRITICAL
  ↓
Final severity assigned
```

### Insight Generation

```
For each event:
  1. Analyze the event
  2. If anomaly detected, add to insights
  3. Track unique insights seen
  
After analyzing all events:
  1. Count critical/high-risk events
  2. Add count insights ("12 critical events detected")
  3. Add failure insights ("147 failed operations")
```

## LLM Understanding

The LLM system prompt has been updated to make it aware of the analysis:

> "The audit tools return data analyzed for security significance:
> - Events are categorized (auth, secret, policy, system, etc.)
> - Severity is assigned (critical, high, medium, low)
> - Key insights are extracted and provided
> - System namespace operations are flagged as critical
> - Failed operations are highlighted"

This helps the LLM:
- Understand what events mean, not just count them
- Prioritize critical events in its response
- Explain findings in business/security terms
- Ask smarter follow-up questions

## Example: User Query with Analysis

### User: "What happened in the last hour?"

**Old Response (dimension counting):**
```
Found 5,247 events.
Top operations: read (86%), write (10%), delete (4%)
Top namespaces: admin (60%), engineering (30%), finance (10%)
Top mount types: kv (50%), approle (30%), secret (20%)
Success rate: 97.2%
```

**New Response (with analysis):**
```
Found 5,247 events in the last hour.

CRITICAL FINDINGS:
- 12 critical events detected (system config, audit changes, policy updates)
- 147 failed operations
- System namespace operations performed

BREAKDOWN BY OPERATION TYPE:
- Secret access operations: 3,200 (61%)
- Authentication attempts: 1,200 (23%)
- Configuration changes: 847 (16%)
  - Audit system modified
  - Policy modified
  - System configuration changed

TOP ACTIVITY:
- 86% read operations (mostly secret access)
- 10% write operations (including configuration changes)
- 4% delete operations

Most Active Namespaces: admin (60%), engineering (30%)

Success Rate: 97.2% (147 failures detected)
```

## Files Modified

- `internal/audit/analyzer.go` - NEW: Event analysis engine
- `internal/audit/summary.go` - Updated: Integrated analysis into SearchSummary
- `internal/audit/tools.go` - Documentation updates

## Future Enhancements

1. **Pattern Detection**
   - Detect brute-force attempts (many failed auth in short time)
   - Detect privilege escalation (token creation patterns)
   - Detect configuration drift (multiple config changes from different sources)

2. **Trend Analysis**
   - Compare current hour to baseline
   - Identify anomalous increase/decrease in operations

3. **Correlation Analysis**
   - Link related events by request ID
   - Identify operation sequences (e.g., "role create followed by multiple failed attempts")

4. **Custom Rules**
   - Allow operators to define custom categories
   - Flag specific path/operation combinations

5. **Risk Scoring**
   - Score each event 0-100 for risk
   - Aggregate to overall risk scores

## Testing the Analyzer

Build and restart vault-audit-mcp:

```bash
cd vault-audit-mcp
go build -o server ./cmd/server
./server
```

Query VaultLens with:
```
"Show me any configuration changes in the last 30 minutes"
```

You should see the LLM highlight critical events and system changes specifically, understanding them as configuration modifications rather than generic log entries.
