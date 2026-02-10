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
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 20 * time.Second,
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
		return nil, err
	}
	defer resp.Body.Close()

	var out QueryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Status != "success" {
		if out.Error != "" {
			return nil, fmt.Errorf("loki query_range failed: %s (%s)", out.Error, out.ErrorType)
		}
		return nil, fmt.Errorf("loki query_range failed: status=%s", out.Status)
	}
	return &out, nil
}
