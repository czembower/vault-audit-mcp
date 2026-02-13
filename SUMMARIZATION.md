# Vault Audit MCP - Data Summarization Strategy

## Overview

To manage token usage in LLM contexts and prevent hitting token limits, vault-audit-mcp now returns **summarized audit data** by default instead of raw event lists.

## Data Reduction Strategy

### 1. Search Events (`audit.search_events`)

**Instead of returning:** All matching events with full Raw JSON data

**Returns:** `SearchSummary` containing:
- **Total event count** - How many events matched the query
- **Time range** - Start and end times queried
- **Statistics** - Total successes and errors
- **Top patterns** - Top 5 namespaces, operations, and mount types
- **Success rate** - Percentage of successful operations (ok vs error)
- **Sample events** - First 5 matching events (without Raw data) for context
- **Summarized flag** - Indicates if results are truncated

**Example response:**
```json
{
  "total_events": 3847,
  "start_time": "2026-02-10T21:00:00Z",
  "end_time": "2026-02-10T22:00:00Z",
  "statistics": {
    "total_success": 3800,
    "total_errors": 47
  },
  "top_namespaces": [
    { "namespace": "admin", "count": 2100 },
    { "namespace": "engineering", "count": 1500 },
    { "namespace": "finance", "count": 247 }
  ],
  "top_operations": [
    { "operation": "read", "count": 3200 },
    { "operation": "write", "count": 600 },
    { "operation": "list", "count": 47 }
  ],
  "success_rate": 0.988,
  "sample_events": [
    { "time": "2026-02-10T21:00:15Z", "namespace": "admin", "operation": "read", ... },
    ...
  ],
  "summarized": true
}
```

### 2. Aggregate (`audit.aggregate`)

**Already efficient** - Returns only count buckets by dimension:
```json
[
  { "key": "admin", "value": 2100 },
  { "key": "engineering", "value": 1500 },
  { "key": "finance", "value": 247 }
]
```

No changes needed - this was already compact.

### 3. Trace Request (`audit.trace`)

**Instead of returning:** All events for a request

**Returns:** `TraceSummary` containing:
- **Request ID** - The traced request ID
- **Total events** - Count of events in the trace
- **Time range** - Start and end times
- **Timeline** - Human-readable description of trace duration
- **First/Last events** - Bookend events for context
- **Namespaces/Operations** - All unique namespaces and operations involved
- **Sample events** - First 3 events (without Raw data) for context
- **Summarized flag** - Indicates if results are truncated

**Example response:**
```json
{
  "request_id": "12345-abcde",
  "total_events": 8,
  "start_time": "2026-02-10T21:45:00Z",
  "end_time": "2026-02-10T21:45:02Z",
  "timeline": "Trace started at 21:45:00 and ended at 21:45:02 (8 events)",
  "first_event": { "time": "2026-02-10T21:45:00Z", "operation": "read", ... },
  "last_event": { "time": "2026-02-10T21:45:02Z", "operation": "write", ... },
  "namespaces": ["admin"],
  "operations": ["read", "write"],
  "sample_events": [...],
  "summarized": false
}
```

## Token Benefits

**Before summarization:**
- 100 events × 2KB per event = 200KB per response
- 200KB × tokens per KB ≈ 50,000 tokens per search

**After summarization:**
- Summary with stats + 5 samples = ~5KB
- 5KB × tokens per KB ≈ 1,250 tokens per search
- **~40x reduction** in typical cases

## LLM Usage Pattern

The LLM now receives:
1. **Summary statistics** - Understand the scope of matching events
2. **Patterns** - See what's most common (top operations, namespaces)
3. **Sample data** - Get concrete examples from the full result set
4. **Summarized flag** - Know if it's seeing full results or a summary

The LLM can then:
- Ask targeted follow-up questions based on patterns
- Request aggregate queries if it needs counts
- Request trace queries if it needs to follow a specific request
- Be aware of data volume ("3,847 events matched, showing summary")

## Configuration (Future Enhancement)

To support both modes, consider adding an environment variable:

```bash
# Return full results (not summarized) for compatibility
AUDIT_INCLUDE_RAW_DATA=true

# Set maximum events before forcing summary-only mode
AUDIT_MAX_EVENTS_FULL_RESPONSE=50
```

## Implementation Details

All summarization functions are in `internal/audit/summary.go`:
- `SummarizeSearch()` - Converts search results to SearchSummary
- `SummarizeTrace()` - Converts trace results to TraceSummary
- Helper functions for sorting and deduplication

The functions strip `Raw` data from events to reduce JSON size significantly.
