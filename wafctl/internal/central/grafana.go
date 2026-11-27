package central

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// grafanaFiles are the provisioning files (secrets are referenced as $VARS, never rendered).
func grafanaFiles() map[string][]byte {
	return map[string][]byte{
		"grafana/provisioning/datasources/waf.yaml": []byte(`# Rendered by wafctl central render — do not edit.
apiVersion: 1
datasources:
  - name: ClickHouse
    uid: ch
    type: grafana-clickhouse-datasource
    jsonData: {host: clickhouse, port: 8123, protocol: http, username: waf_ro, defaultDatabase: waf}
    secureJsonData: {password: $WAF_CH_RO_PASSWORD}
  - name: Prometheus
    uid: prom
    type: prometheus
    url: http://prometheus:9090
`),
		"grafana/provisioning/dashboards/waf.yaml": []byte(`# Rendered by wafctl central render — do not edit.
apiVersion: 1
providers:
  - name: waf
    folder: WAF
    type: file
    allowUiUpdates: false
    options: {path: /var/lib/grafana-dashboards}
`),
	}
}

// GrafanaAPI is a minimal Grafana HTTP API client (basic auth as admin).
type GrafanaAPI struct {
	URL, User, Password string
	HTTP                *http.Client
}

// User is a Grafana user (subset of /api/users and /api/org/users).
type User struct {
	ID    int    `json:"userId,omitempty"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// NewUserRequest is the body of POST /api/admin/users.
type NewUserRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Login    string `json:"login"`
	Password string `json:"password"`
	OrgID    int    `json:"OrgId"`
}

func (g *GrafanaAPI) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.URL, "/")+path, r)
	if err != nil {
		return err
	}
	req.SetBasicAuth(g.User, g.Password)
	req.Header.Set("Content-Type", "application/json")
	hc := g.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("grafana: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("grafana: %s %s: HTTP %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(b))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// AddUser creates a user in org 1 and sets its role.
func (g *GrafanaAPI) AddUser(ctx context.Context, login, name, email, role, password string) (int, error) {
	if name == "" {
		name = login
	}
	if email == "" {
		email = login + "@localhost"
	}
	var res struct {
		ID int `json:"id"`
	}
	if err := g.do(ctx, http.MethodPost, "/api/admin/users", NewUserRequest{Name: name, Email: email, Login: login, Password: password, OrgID: 1}, &res); err != nil {
		return 0, err
	}
	if err := g.do(ctx, http.MethodPatch, fmt.Sprintf("/api/org/users/%d", res.ID), map[string]string{"role": role}, nil); err != nil {
		return res.ID, err
	}
	return res.ID, nil
}

// Users lists the users of the current org.
func (g *GrafanaAPI) Users(ctx context.Context) ([]User, error) {
	var us []User
	err := g.do(ctx, http.MethodGet, "/api/org/users", nil, &us)
	return us, err
}

// RandomPassword returns n random alphanumeric characters.
func RandomPassword(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[k.Int64()]
	}
	return string(b), nil
}

// ValidRole reports whether r is a Grafana org role.
func ValidRole(r string) bool { return r == "Admin" || r == "Editor" || r == "Viewer" }
