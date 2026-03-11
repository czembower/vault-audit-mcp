package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"vault-audit-mcp/internal/audit"
	"vault-audit-mcp/internal/loki"
)

func main() {
	lokiURL := os.Getenv("LOKI_URL")
	if lokiURL == "" {
		lokiURL = "http://localhost:3100"
	}

	opts := &loki.ClientOptions{
		BearerToken:   os.Getenv("LOKI_BEARER_TOKEN"),
		TLSSkipVerify: strings.EqualFold(os.Getenv("LOKI_TLS_SKIP_VERIFY"), "true"),
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "vault-audit-mcp",
		Version: "0.1.0",
	}, nil)

	// Optional: override base Loki stream selector labels.
	// Example: LOKI_BASE_LABELS='{"kubernetes_namespace_name":"hashicorp-vault"}'
	var labelsCfg *audit.LabelConfig
	if raw := os.Getenv("LOKI_BASE_LABELS"); raw != "" {
		var baseLabels map[string]string
		if err := json.Unmarshal([]byte(raw), &baseLabels); err != nil {
			log.Fatalf("invalid LOKI_BASE_LABELS JSON: %v", err)
		}
		labelsCfg = &audit.LabelConfig{
			BaseLabels:     baseLabels,
			UseVaultLabels: false,
		}
		log.Printf("using custom base labels: %v (vault label filters disabled)", baseLabels)
	}

	backend := audit.NewLokiBackend(loki.NewClient(lokiURL, opts), labelsCfg)
	svc := audit.NewService(backend)
	svc.AddTools(server)

	// Handle resource requests - required for MCP protocol
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
