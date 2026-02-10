package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"vault-audit-mcp/internal/audit"
	"vault-audit-mcp/internal/loki"
)

func main() {
	lokiURL := os.Getenv("LOKI_URL")
	if lokiURL == "" {
		lokiURL = "http://localhost:3100"
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "vault-audit-mcp",
		Version: "0.1.0",
	}, nil)

	backend := audit.NewLokiBackend(loki.NewClient(lokiURL))
	svc := audit.NewService(backend)
	svc.AddTools(server)

	// Handle resource requests - required for MCP protocol
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
