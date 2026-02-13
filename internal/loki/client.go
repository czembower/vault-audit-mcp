package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	// Configure transport to handle large responses and prevent connection reuse issues
	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		// Add these to prevent EOF on large responses
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout:   90 * time.Second,
			Transport: transport,
		},
	}
}

// QueryRange calls /loki/api/v1/query_range.
// start/end should be RFC3339 or unix ns as string; we’ll send RFC3339 for simplicity.
func (c *Client) QueryRange(ctx context.Context, query string, start, end time.Time, limit int) (*QueryRangeResponse, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, err
	}
	u.Path = "/loki/api/v1/query_range"

	q := u.Query()
	q.Set("query", query)
	q.Set("start", start.UTC().Format(time.RFC3339Nano))
	q.Set("end", end.UTC().Format(time.RFC3339Nano))
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code before decoding to provide better error messages
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var out QueryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode loki response: %w", err)
	}
	if out.Status != "success" {
		if out.Error != "" {
			return nil, fmt.Errorf("loki query_range failed: %s (%s)", out.Error, out.ErrorType)
		}
		return nil, fmt.Errorf("loki query_range failed: status=%s", out.Status)
	}
	return &out, nil
}
