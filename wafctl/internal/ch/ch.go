// Package ch queries ClickHouse over HTTP (D18) or offline over raw JSONL with clickhouse local.
// SQL text is always constant; user values travel only as {name:Type} parameters.
package ch

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"nginxawswaf/wafctl/internal/secrets"
)

// Querier runs a parameterised query and streams JSONEachRow rows.
type Querier interface {
	Query(ctx context.Context, sql string, params map[string]string, out func(json.RawMessage) error) error
}

// Client is the HTTP implementation.
type Client struct {
	URL, User, Password string
	HTTP                *http.Client
}

// FromEnv builds a client from WAF_CH_URL / WAF_CH_USER / WAF_CH_PASSWORD; the password defaults
// to WAF_CH_RO_PASSWORD from <configDir>/secrets.env.
func FromEnv(configDir string) *Client {
	c := &Client{URL: getenv("WAF_CH_URL", "http://127.0.0.1:8123"), User: getenv("WAF_CH_USER", "waf_ro"),
		Password: os.Getenv("WAF_CH_PASSWORD"), HTTP: &http.Client{Timeout: 5 * time.Minute}}
	if c.Password == "" {
		if m, err := secrets.Load(filepath.Join(configDir, "secrets.env")); err == nil {
			c.Password = m["WAF_CH_RO_PASSWORD"]
		}
	}
	return c
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// Settings sent with every query (64-bit integers as JSON numbers).
var Settings = map[string]string{"output_format_json_quote_64bit_integers": "0"}

// Query POSTs the SQL with param_<name> URL parameters and default_format=JSONEachRow.
func (c *Client) Query(ctx context.Context, sql string, params map[string]string, out func(json.RawMessage) error) error {
	v := url.Values{}
	v.Set("default_format", "JSONEachRow")
	for k, s := range Settings {
		v.Set(k, s)
	}
	for k, p := range params {
		v.Set("param_"+k, p)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/?"+v.Encode(), bytes.NewBufferString(sql))
	if err != nil {
		return err
	}
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("clickhouse: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("clickhouse: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return decodeLines(resp.Body, out)
}

// decodeLines streams one JSON object per line to out.
func decodeLines(r io.Reader, out func(json.RawMessage) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		l := bytes.TrimSpace(sc.Bytes())
		if len(l) == 0 {
			continue
		}
		if !json.Valid(l) {
			return fmt.Errorf("clickhouse: invalid JSON row: %.200s", l)
		}
		if err := out(append(json.RawMessage(nil), l...)); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Collect runs q and decodes all rows into a slice of T.
func Collect[T any](ctx context.Context, q Querier, sql string, params map[string]string) ([]T, error) {
	var rows []T
	err := q.Query(ctx, sql, params, func(m json.RawMessage) error {
		var r T
		if err := json.Unmarshal(m, &r); err != nil {
			return err
		}
		rows = append(rows, r)
		return nil
	})
	return rows, err
}
