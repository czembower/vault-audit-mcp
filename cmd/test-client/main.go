package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	// Parse flags
	operation := flag.String("op", "search", "Operation: search, aggregate, or trace")
	namespace := flag.String("namespace", "", "Filter by namespace (optional)")
	operationFilter := flag.String("operation", "", "Filter by operation (optional)")
	mountType := flag.String("mount-type", "", "Filter by mount type (optional)")
	status := flag.String("status", "", "Filter by status: ok or error (optional)")
	aggregateBy := flag.String("by", "vault_operation", "Aggregation dimension (for aggregate)")
	requestID := flag.String("request-id", "", "Request ID to trace (for trace)")
	limit := flag.Int("limit", 10, "Max results (default 10)")
	startTime := flag.String("start", "", "Start time (RFC3339, default now-15m)")
	endTime := flag.String("end", "", "End time (RFC3339, default now)")
	flag.Parse()

	ctx := context.Background()

	// Create a new client
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)

	// Connect to server over stdin/stdout
	fmt.Println("Connecting to MCP server...")
	transport := &mcp.CommandTransport{Command: exec.Command("./server")}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatalf("Connect failed: %v", err)
	}
	defer session.Close()

	// List available tools
	fmt.Println("\nAvailable tools:")
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("ListTools failed: %v", err)
	}
	for _, tool := range tools.Tools {
		fmt.Printf("  • %s\n    %s\n", tool.Name, tool.Description)
	}

	// Execute the requested operation
	fmt.Printf("\nExecuting: %s\n", *operation)
	var params *mcp.CallToolParams

	switch *operation {
	case "search":
		args := map[string]any{
			"limit":         *limit,
			"namespace":     *namespace,
			"operation":     *operationFilter,
			"mount_type":    *mountType,
			"status":        *status,
			"start_rfc3339": *startTime,
			"end_rfc3339":   *endTime,
		}
		removeEmptyStrings(args)
		params = &mcp.CallToolParams{
			Name:      "audit.search_events",
			Arguments: args,
		}

	case "aggregate":
		args := map[string]any{
			"by":            *aggregateBy,
			"namespace":     *namespace,
			"operation":     *operationFilter,
			"mount_type":    *mountType,
			"status":        *status,
			"start_rfc3339": *startTime,
			"end_rfc3339":   *endTime,
		}
		removeEmptyStrings(args)
		params = &mcp.CallToolParams{
			Name:      "audit.aggregate",
			Arguments: args,
		}

	case "trace":
		if *requestID == "" {
			log.Fatalf("request-id is required for trace operation")
		}
		args := map[string]any{
			"request_id":    *requestID,
			"limit":         *limit,
			"start_rfc3339": *startTime,
			"end_rfc3339":   *endTime,
		}
		removeEmptyStrings(args)
		params = &mcp.CallToolParams{
			Name:      "audit.trace",
			Arguments: args,
		}

	default:
		log.Fatalf("Unknown operation: %s", *operation)
	}

	// Call the tool
	fmt.Println("\nCalling tool...")
	res, err := session.CallTool(ctx, params)
	if err != nil {
		log.Fatalf("CallTool failed: %v", err)
	}

	// Print results
	if res.IsError {
		fmt.Println("\n✗ Tool returned error:")
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				fmt.Printf("  %s\n", tc.Text)
			}
		}
	} else {
		fmt.Println("\n✓ Tool succeeded!")
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				// Try to parse as JSON for pretty printing
				var data interface{}
				if err := json.Unmarshal([]byte(tc.Text), &data); err == nil {
					b, _ := json.MarshalIndent(data, "", "  ")
					fmt.Printf("%s\n", string(b))
				} else {
					fmt.Printf("%s\n", tc.Text)
				}
			}
		}
	}
}

func removeEmptyStrings(m map[string]any) {
	for k, v := range m {
		if s, ok := v.(string); ok && s == "" {
			delete(m, k)
		}
	}
}
