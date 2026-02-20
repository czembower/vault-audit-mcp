package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

const (
	queryRangeMaxAttempts   = 3
	queryRangeInitialBackoff = 250 * time.Millisecond
)

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

	var lastErr error
	for attempt := 1; attempt <= queryRangeMaxAttempts; attempt++ {
		out, retryable, err := c.queryRangeOnce(ctx, u.String())
		if err == nil {
			return out, nil
		}

		lastErr = err
		if !retryable || attempt == queryRangeMaxAttempts || ctx.Err() != nil {
			break
		}

		backoff := queryRangeInitialBackoff * time.Duration(1<<(attempt-1))
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("loki query_range canceled while retrying: %w", ctx.Err())
		case <-timer.C:
		}
	}

	return nil, lastErr
}

func (c *Client) queryRangeOnce(ctx context.Context, url string) (*QueryRangeResponse, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, isRetryableTransportErr(err), fmt.Errorf("loki HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code before decoding to provide better error messages.
	if resp.StatusCode != http.StatusOK {
		retryable := isRetryableHTTPStatus(resp.StatusCode)
		return nil, retryable, fmt.Errorf("loki returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var out QueryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, isRetryableDecodeErr(err), fmt.Errorf("failed to decode loki response: %w", err)
	}
	if out.Status != "success" {
		if out.Error != "" {
			return nil, false, fmt.Errorf("loki query_range failed: %s (%s)", out.Error, out.ErrorType)
		}
		return nil, false, fmt.Errorf("loki query_range failed: status=%s", out.Status)
	}
	return &out, false, nil
}

func isRetryableHTTPStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

func isRetryableDecodeErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func isRetryableTransportErr(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "unexpected eof")
}
